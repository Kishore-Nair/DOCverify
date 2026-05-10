document.addEventListener('DOMContentLoaded', () => {
    // ── Mobile menu ──────────────────────────────────────────
    const menuToggle = document.getElementById('menu-toggle');
    const menuClose = document.getElementById('menu-close');
    const sidebar = document.getElementById('sidebar');

    if (menuToggle && sidebar) {
        menuToggle.addEventListener('click', () => sidebar.classList.add('open'));
    }
    if (menuClose && sidebar) {
        menuClose.addEventListener('click', () => sidebar.classList.remove('open'));
    }

    // ── Generic dropzone setup ───────────────────────────────
    document.querySelectorAll('.dropzone').forEach(zone => {
        const input = zone.querySelector('input[type="file"]');
        if (!input) return;

        zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
        zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
        zone.addEventListener('drop', e => {
            e.preventDefault();
            zone.classList.remove('drag-over');
            if (e.dataTransfer.files.length) {
                input.files = e.dataTransfer.files;
                updateDropzoneText(zone, e.dataTransfer.files[0].name);
            }
        });
        input.addEventListener('change', () => {
            if (input.files.length) updateDropzoneText(zone, input.files[0].name);
        });
    });

    function updateDropzoneText(zone, filename) {
        const txt = zone.querySelector('.dropzone-text');
        if (txt) { txt.textContent = `Selected: ${filename}`; txt.style.color = 'var(--primary-light)'; }
    }

    // ── Upload form (JWT upload) ─────────────────────────────
    const uploadForm = document.getElementById('upload-form');
    if (uploadForm) {
        uploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const fileInput = uploadForm.querySelector('input[type="file"]');
            if (!fileInput || !fileInput.files.length) return alert('Please select a file.');

            const formData = new FormData(uploadForm);
            const progress = document.getElementById('upload-progress');
            const formContainer = document.getElementById('upload-form-container');
            const resultCard = document.getElementById('upload-result');
            const errorCard = document.getElementById('upload-error');
            const submitBtn = document.getElementById('upload-submit');

            // Show progress
            if (submitBtn) submitBtn.disabled = true;
            if (progress) progress.style.display = 'block';

            // Animate steps
            const animateStep = (n) => {
                for (let i = 1; i <= 4; i++) {
                    const s = document.getElementById(`step-${i}`);
                    if (!s) continue;
                    s.classList.remove('active', 'done');
                    if (i < n) s.classList.add('done');
                    else if (i === n) s.classList.add('active');
                }
            };

            try {
                animateStep(1);
                // We need a JWT token. Get it from cookie or localStorage.
                // For web form uploads, we'll POST directly to the web route instead.
                // Actually, let's use the session-based web upload route.
                
                // Use the session-based POST to /upload (web form)
                const resp = await fetch('/upload', {
                    method: 'POST',
                    body: (() => {
                        const fd = new FormData();
                        fd.append('document', fileInput.files[0]);
                        fd.append('doc_type', formData.get('doc_type'));
                        fd.append('issuer_name', formData.get('issuer_name'));
                        return fd;
                    })(),
                    redirect: 'follow',
                });

                animateStep(2);
                await new Promise(r => setTimeout(r, 600));
                animateStep(3);
                await new Promise(r => setTimeout(r, 600));
                animateStep(4);
                await new Promise(r => setTimeout(r, 400));

                // The web route redirects to /report/<id> on success.
                // If we got a redirect, follow it.
                if (resp.redirected) {
                    window.location.href = resp.url;
                    return;
                }

                // If we got HTML back (success or error with flash), just reload.
                window.location.href = '/dashboard';

            } catch (err) {
                console.error('Upload error:', err);
                if (progress) progress.style.display = 'none';
                if (errorCard) {
                    errorCard.style.display = 'block';
                    const msg = document.getElementById('error-message');
                    if (msg) msg.textContent = err.message || 'Network error. Please try again.';
                }
                if (submitBtn) submitBtn.disabled = false;
            }
        });
    }

    // ── Verify Tabs ──────────────────────────────────────────
    const tabUpload = document.getElementById('tab-upload');
    const tabHash = document.getElementById('tab-hash');
    const contentUpload = document.getElementById('content-upload');
    const contentHash = document.getElementById('content-hash');

    if (tabUpload && tabHash) {
        tabUpload.addEventListener('click', () => {
            tabUpload.className = 'btn active';
            tabHash.className = 'btn btn--secondary';
            if (contentUpload) contentUpload.style.display = 'block';
            if (contentHash) contentHash.style.display = 'none';
        });
        tabHash.addEventListener('click', () => {
            tabHash.className = 'btn active';
            tabUpload.className = 'btn btn--secondary';
            if (contentHash) contentHash.style.display = 'block';
            if (contentUpload) contentUpload.style.display = 'none';
        });
    }

    // ── Verify by Hash ───────────────────────────────────────
    const hashForm = document.getElementById('verify-hash-form');
    if (hashForm) {
        hashForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const input = hashForm.querySelector('input[name="sha256_hash"]');
            if (!input || !input.value.trim()) return;
            await doVerify('/verify/hash', { sha256_hash: input.value.trim().toLowerCase() });
        });
    }

    // ── Verify by Upload ─────────────────────────────────────
    const uploadVerifyForm = document.getElementById('verify-upload-form');
    if (uploadVerifyForm) {
        uploadVerifyForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const fileInput = uploadVerifyForm.querySelector('input[type="file"]');
            if (!fileInput || !fileInput.files.length) return alert('Please select a file.');
            const fd = new FormData();
            fd.append('file', fileInput.files[0]);
            await doVerify('/verify/upload', fd, true);
        });
    }

    async function doVerify(url, body, isFormData = false) {
        const loading = document.getElementById('verify-loading');
        const result = document.getElementById('verify-result');
        const upload = document.getElementById('content-upload');
        const hash = document.getElementById('content-hash');

        if (upload) upload.style.display = 'none';
        if (hash) hash.style.display = 'none';
        if (loading) loading.style.display = 'block';
        if (result) result.style.display = 'none';

        try {
            const opts = isFormData
                ? { method: 'POST', body }
                : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
            
            const resp = await fetch(url, opts);
            const data = await resp.json();
            if (loading) loading.style.display = 'none';
            renderVerifyResult(data, result);
        } catch (err) {
            if (loading) loading.style.display = 'none';
            if (result) {
                result.style.display = 'block';
                result.innerHTML = `
                    <div class="text-center">
                        <div class="verify-result-icon">⚠️</div>
                        <div class="verify-result-title" style="color: var(--warning);">Network Error</div>
                        <p style="color: var(--text-muted);">${err.message}</p>
                        <button class="btn btn--primary mt-4" onclick="location.reload()">Try Again</button>
                    </div>`;
            }
        }
    }

    function renderVerifyResult(data, container) {
        if (!container) return;
        container.style.display = 'block';

        if (data.success && data.data) {
            const d = data.data;
            const doc = d.document || {};
            const isVerified = d.status === 'verified';
            const isRevoked = d.status === 'revoked';
            const icon = isVerified ? '✅' : isRevoked ? '⚠️' : '❌';
            const color = isVerified ? 'var(--success)' : isRevoked ? 'var(--warning)' : 'var(--danger)';
            const label = isVerified ? 'Document Authentic' : isRevoked ? 'Document Revoked' : 'Not Found';

            container.innerHTML = `
                <div class="text-center mb-4">
                    <div class="verify-result-icon">${icon}</div>
                    <div class="verify-result-title" style="color: ${color};">${label}</div>
                </div>
                <table class="table" style="font-size: 0.85rem;">
                    <tbody>
                        <tr><th>Status</th><td><span class="badge badge--${d.status}">${(d.status || '').toUpperCase()}</span></td></tr>
                        ${doc.original_name ? `<tr><th>Document</th><td>${doc.original_name}</td></tr>` : ''}
                        ${doc.doc_type ? `<tr><th>Type</th><td>${doc.doc_type}</td></tr>` : ''}
                        ${doc.issuer_name ? `<tr><th>Issuer</th><td>${doc.issuer_name}</td></tr>` : ''}
                        ${doc.sha256_hash ? `<tr><th>SHA-256</th><td class="text-mono" style="word-break:break-all; font-size:0.8rem;">${doc.sha256_hash}</td></tr>` : ''}
                        ${doc.upload_date ? `<tr><th>Upload Date</th><td>${new Date(doc.upload_date).toLocaleString()}</td></tr>` : ''}
                    </tbody>
                </table>
                <div class="text-center mt-4">
                    <button class="btn btn--secondary" onclick="location.reload()">Verify Another</button>
                </div>`;
        } else {
            container.innerHTML = `
                <div class="text-center">
                    <div class="verify-result-icon">❌</div>
                    <div class="verify-result-title" style="color: var(--danger);">Not Found</div>
                    <p style="color: var(--text-muted); margin-top: 0.5rem;">${data.message || 'Document not found in the registry.'}</p>
                    <button class="btn btn--secondary mt-4" onclick="location.reload()">Verify Another</button>
                </div>`;
        }
    }

    // ── Auto-dismiss flash messages ──────────────────────────
    document.querySelectorAll('.flash').forEach(el => {
        setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 5000);
    });
});
