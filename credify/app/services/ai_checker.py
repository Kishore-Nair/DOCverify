"""Document tampering detection service (heuristic, no ML).

Runs lightweight checks on PDFs and images to flag potentially
manipulated documents.  Uses only **pypdf** and **Pillow** — no GPU
or ML models required.

Public entry point
------------------
``analyze_document(file_path)`` — runs every applicable check and
returns a unified verdict dict.

Individual checks
-----------------
- ``metadata_check``          (PDF)        – suspicious creator / date mismatch
- ``font_consistency_check``  (PDF)        – too many font families
- ``image_noise_check``       (JPG / PNG)  – Error Level Analysis

Confidence scoring
------------------
``calculate_confidence_score`` combines the check results into a
0.0 – 1.0 score (1.0 = authentic, 0.0 = highly suspicious).
"""

import io
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Extensions handled by each check family
_PDF_EXTS = {".pdf"}
_IMG_EXTS = {".jpg", ".jpeg", ".png"}

# Suspicious creator / producer strings (case-insensitive substrings)
_SUSPICIOUS_CREATORS = [
    "photoshop",
    "gimp",
    "adobe acrobat edit",
    "foxit",
    "pdf editor",
    "nitro",
    "inkscape",
    "libreoffice draw",
]


# ===================================================================== #
#  1.  Metadata check  (PDF)                                            #
# ===================================================================== #


def metadata_check(file_path: str) -> dict:
    """Inspect PDF metadata for signs of editing or tampering.

    Flags raised:
    - Creator or Producer contains a known image-editing tool.
    - Modification date differs from creation date.
    - The PDF is encrypted or has restricted permissions.

    Returns:
        dict with ``score`` (0.0–1.0), ``flags`` (list[str]),
        ``metadata`` (raw metadata dict).
    """
    flags: list[str] = []
    score = 1.0
    raw_meta: dict = {}

    try:
        from pypdf import PdfReader

        reader = PdfReader(file_path)

        # -- encryption / permissions --
        if reader.is_encrypted:
            flags.append("PDF is encrypted — may be hiding modifications")
            score -= 0.25

        meta = reader.metadata or {}
        raw_meta = {k: str(v) for k, v in (meta.items() if hasattr(meta, "items") else [])}

        # -- suspicious creator / producer --
        creator = str(meta.get("/Creator", "")).lower()
        producer = str(meta.get("/Producer", "")).lower()
        for keyword in _SUSPICIOUS_CREATORS:
            if keyword in creator or keyword in producer:
                flags.append(
                    f"Suspicious creator/producer: contains '{keyword}'"
                )
                score -= 0.3
                break  # one flag is enough

        # -- creation vs modification date --
        creation = meta.get("/CreationDate")
        modification = meta.get("/ModDate")
        if creation and modification:
            creation_str = str(creation).strip()
            modification_str = str(modification).strip()
            if creation_str != modification_str:
                flags.append(
                    f"Modification date ({modification_str}) differs from "
                    f"creation date ({creation_str})"
                )
                score -= 0.2

    except Exception as exc:
        logger.warning("metadata_check error: %s", exc)
        flags.append(f"Could not read PDF metadata: {exc}")
        score -= 0.1

    score = max(score, 0.0)
    logger.debug("metadata_check score=%.2f flags=%s", score, flags)
    return {"score": round(score, 3), "flags": flags, "metadata": raw_meta}


# ===================================================================== #
#  2.  Font consistency check  (PDF)                                    #
# ===================================================================== #


def font_consistency_check(file_path: str) -> dict:
    """Check for an unusual number of font families in a PDF.

    Official documents typically use 1–3 fonts.  More than 4 distinct
    font families is flagged as suspicious (may indicate copy-paste
    from multiple sources).

    Returns:
        dict with ``score``, ``flags``, ``fonts`` (list of names),
        ``font_count``.
    """
    flags: list[str] = []
    score = 1.0
    font_names: set[str] = set()

    try:
        from pypdf import PdfReader

        reader = PdfReader(file_path)

        for page in reader.pages:
            resources = page.get("/Resources")
            if not resources:
                continue
            fonts_dict = resources.get("/Font")
            if not fonts_dict:
                continue

            # fonts_dict can be an IndirectObject — resolve it
            if hasattr(fonts_dict, "get_object"):
                fonts_dict = fonts_dict.get_object()

            for font_ref in fonts_dict.values():
                font_obj = font_ref.get_object() if hasattr(font_ref, "get_object") else font_ref
                base_font = str(font_obj.get("/BaseFont", "Unknown"))
                # Normalise: strip subset prefix like "ABCDEF+"
                if "+" in base_font:
                    base_font = base_font.split("+", 1)[1]
                # Extract family (before the dash for style variants)
                family = base_font.split("-")[0].split(",")[0].strip("/")
                font_names.add(family)

        count = len(font_names)
        if count > 4:
            flags.append(
                f"Unusually high number of font families ({count}): "
                f"{', '.join(sorted(font_names))}"
            )
            # Penalty scales with how far above 4 we are
            score -= min(0.15 * (count - 4), 0.6)

    except Exception as exc:
        logger.warning("font_consistency_check error: %s", exc)
        flags.append(f"Could not analyse fonts: {exc}")
        score -= 0.05

    score = max(score, 0.0)
    logger.debug("font_consistency_check score=%.2f fonts=%s", score, font_names)
    return {
        "score": round(score, 3),
        "flags": flags,
        "fonts": sorted(font_names),
        "font_count": len(font_names),
    }


# ===================================================================== #
#  3.  Image noise / ELA check  (JPG / PNG)                             #
# ===================================================================== #


def image_noise_check(file_path: str) -> dict:
    """Perform a simple Error Level Analysis (ELA) on an image.

    Process:
    1. Re-save the image as JPEG at 95 % quality into memory.
    2. Compute the per-pixel absolute difference with the original.
    3. High mean / max difference in supposedly uniform regions
       indicates potential splicing or cloning.

    Also checks for unusual pixel variance in the overall image.

    Returns:
        dict with ``score``, ``flags``, ``ela_mean``, ``ela_max``,
        ``variance``.
    """
    flags: list[str] = []
    score = 1.0
    ela_mean = 0.0
    ela_max = 0
    variance = 0.0

    try:
        from PIL import Image
        import numpy as np

        original = Image.open(file_path).convert("RGB")

        # -- ELA --
        buffer = io.BytesIO()
        original.save(buffer, format="JPEG", quality=95)
        buffer.seek(0)
        resaved = Image.open(buffer).convert("RGB")

        orig_arr = np.asarray(original, dtype=np.float32)
        resaved_arr = np.asarray(resaved, dtype=np.float32)

        diff = np.abs(orig_arr - resaved_arr)
        ela_mean = float(np.mean(diff))
        ela_max = int(np.max(diff))

        # Thresholds tuned empirically for JPEG artefacts
        if ela_mean > 15:
            flags.append(
                f"High ELA mean difference ({ela_mean:.1f}) — "
                "possible region manipulation"
            )
            score -= 0.35
        elif ela_mean > 8:
            flags.append(
                f"Moderate ELA mean difference ({ela_mean:.1f}) — "
                "worth manual review"
            )
            score -= 0.15

        if ela_max > 200:
            flags.append(
                f"ELA max difference spike ({ela_max}) — "
                "localised editing suspected"
            )
            score -= 0.2

        # -- Overall pixel variance --
        variance = float(np.var(orig_arr))
        if variance < 100:
            flags.append(
                f"Very low pixel variance ({variance:.0f}) — "
                "image may be synthetically generated"
            )
            score -= 0.15

    except ImportError:
        logger.warning("numpy not installed — skipping ELA, using Pillow-only fallback")
        score, flags, ela_mean, ela_max, variance = _image_noise_fallback(
            file_path, score, flags
        )
    except Exception as exc:
        logger.warning("image_noise_check error: %s", exc)
        flags.append(f"Could not analyse image: {exc}")
        score -= 0.05

    score = max(score, 0.0)
    logger.debug(
        "image_noise_check score=%.2f ela_mean=%.1f ela_max=%d var=%.0f",
        score, ela_mean, ela_max, variance,
    )
    return {
        "score": round(score, 3),
        "flags": flags,
        "ela_mean": round(ela_mean, 2),
        "ela_max": ela_max,
        "variance": round(variance, 2),
    }


def _image_noise_fallback(file_path, score, flags):
    """Pillow-only fallback when numpy is not available."""
    from PIL import Image, ImageStat

    img = Image.open(file_path).convert("RGB")
    stat = ImageStat.Stat(img)

    # Use stddev per channel as a rough proxy for variance
    avg_stddev = sum(stat.stddev) / len(stat.stddev)
    variance = avg_stddev ** 2

    if avg_stddev < 10:
        flags.append(
            f"Very low pixel stddev ({avg_stddev:.1f}) — "
            "image may be synthetically generated"
        )
        score -= 0.15

    return score, flags, 0.0, 0, variance


# ===================================================================== #
#  4.  Confidence scoring                                               #
# ===================================================================== #

# Weights per check family
_WEIGHTS = {
    "metadata": 0.40,
    "font": 0.30,
    "image": 0.30,
}


def calculate_confidence_score(checks: dict) -> float:
    """Combine individual check scores into one 0.0 – 1.0 confidence.

    Weights:
        metadata  40 %
        font      30 %
        image     30 %

    If a check was not run (e.g. image check on a PDF) its weight is
    redistributed proportionally among the checks that *were* run.

    Args:
        checks: dict mapping check name → sub-dict with a ``score`` key.

    Returns:
        float in [0.0, 1.0].  1.0 = definitely authentic.
    """
    active_weight = 0.0
    weighted_sum = 0.0

    for name, weight in _WEIGHTS.items():
        if name in checks and "score" in checks[name]:
            active_weight += weight
            weighted_sum += weight * checks[name]["score"]

    if active_weight == 0:
        return 1.0  # no checks ran — assume authentic

    confidence = weighted_sum / active_weight
    return round(max(0.0, min(1.0, confidence)), 3)


# ===================================================================== #
#  5.  Unified entry point                                              #
# ===================================================================== #

_SUSPICION_THRESHOLD = 0.6


def analyze_document(file_path: str) -> dict:
    """Run all applicable checks on a document.

    Returns:
        dict with keys:
            - is_suspicious     (bool)
            - confidence_score  (float 0.0–1.0)
            - flags             (list[str])
            - checks            (dict of individual check results)
            - verdict           (str: LEGIT / SUSPICIOUS / REJECTED)
            - report            (str: human-readable summary)
    """
    ext = os.path.splitext(file_path)[1].lower()
    checks: dict = {}
    all_flags: list[str] = []

    # -- PDF checks --
    if ext in _PDF_EXTS:
        meta = metadata_check(file_path)
        checks["metadata"] = meta
        all_flags.extend(meta["flags"])

        font = font_consistency_check(file_path)
        checks["font"] = font
        all_flags.extend(font["flags"])

    # -- Image checks --
    if ext in _IMG_EXTS:
        img = image_noise_check(file_path)
        checks["image"] = img
        all_flags.extend(img["flags"])

    # -- For non-PDF / non-image files, run a basic size check --
    if not checks:
        size = os.path.getsize(file_path)
        basic_score = 1.0
        if size == 0:
            all_flags.append("File is empty (0 bytes)")
            basic_score = 0.2
        elif size < 100:
            all_flags.append(f"File is suspiciously small ({size} bytes)")
            basic_score = 0.7
        checks["metadata"] = {"score": basic_score, "flags": all_flags}

    confidence = calculate_confidence_score(checks)
    is_suspicious = confidence < _SUSPICION_THRESHOLD

    # Verdict mapping
    if confidence >= 0.8:
        verdict = "LEGIT"
    elif confidence >= _SUSPICION_THRESHOLD:
        verdict = "SUSPICIOUS"
    else:
        verdict = "REJECTED"

    # Build human-readable report
    report_lines = [
        f"Document: {os.path.basename(file_path)}",
        f"Confidence: {confidence:.1%}",
        f"Verdict: {verdict}",
    ]
    if all_flags:
        report_lines.append(f"Flags ({len(all_flags)}):")
        for f in all_flags:
            report_lines.append(f"  ⚠ {f}")
    else:
        report_lines.append("No issues detected.")

    report = "\n".join(report_lines)

    logger.info(
        "analyze_document %s  confidence=%.3f  verdict=%s  flags=%d",
        os.path.basename(file_path), confidence, verdict, len(all_flags),
    )

    return {
        "is_suspicious": is_suspicious,
        "confidence_score": confidence,
        "flags": all_flags,
        "checks": checks,
        "verdict": verdict,
        "report": report,
    }


# ===================================================================== #
#  Backward-compat wrapper used by documents.py                         #
# ===================================================================== #


def check_document(file_path: str) -> dict:
    """Legacy wrapper — returns {score, verdict, details}.

    Kept so ``documents.py`` does not need to change its call-site
    contract yet.
    """
    result = analyze_document(file_path)
    return {
        "score": round(result["confidence_score"] * 100, 1),
        "verdict": result["verdict"],
        "details": result["flags"] if result["flags"] else ["✅ No issues detected"],
    }
