document.addEventListener('DOMContentLoaded', () => {
    // Mobile menu toggle
    const menuToggle = document.getElementById('menu-toggle');
    const menuClose = document.getElementById('menu-close');
    const sidebar = document.getElementById('sidebar');

    if (menuToggle && sidebar) {
        menuToggle.addEventListener('click', () => {
            sidebar.classList.add('open');
        });
    }

    if (menuClose && sidebar) {
        menuClose.addEventListener('click', () => {
            sidebar.classList.remove('open');
        });
    }

    // Dropzone functionality
    const dropzone = document.querySelector('.dropzone');
    const fileInput = document.querySelector('.dropzone input[type="file"]');
    const progressContainer = document.querySelector('.progress-bar-container');

    if (dropzone && fileInput) {
        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('drag-over');
        });

        dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('drag-over');
        });

        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('drag-over');
            
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                updateDropzoneText(e.dataTransfer.files[0].name);
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length) {
                updateDropzoneText(fileInput.files[0].name);
            }
        });

        // Form submission with progress
        const form = dropzone.closest('form');
        if (form) {
            form.addEventListener('submit', () => {
                if (fileInput.files.length && progressContainer) {
                    progressContainer.style.display = 'block';
                    dropzone.style.opacity = '0.5';
                    dropzone.style.pointerEvents = 'none';
                }
            });
        }
    }

    function updateDropzoneText(filename) {
        const textElement = dropzone.querySelector('.dropzone-text');
        if (textElement) {
            textElement.textContent = `Selected: ${filename}`;
        }
    }
});
