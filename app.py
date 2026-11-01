import hashlib
import io
import json
import mimetypes
import os
import requests
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
import streamlit as st
from PIL import Image, UnidentifiedImageError
from pypdf import PdfReader

load_dotenv(Path(__file__).resolve().parent / ".env", override=True)

APP_NAME = "TRACEWEAVE"
MAX_BYTES = 25 * 1024 * 1024

st.set_page_config(page_title="TRACEWEAVE | Forensic Studio", page_icon="🧵", layout="wide", initial_sidebar_state="expanded")

# ---------- Styling ----------
st.markdown(r"""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');
:root { --bg:#061014; --panel:#0b1a20; --panel2:#0d2026; --line:#18333b; --text:#e7f3f5; --muted:#91aab2; --green:#19e69b; --red:#ff5266; --amber:#ffc857; }
html, body, [class*="css"] { font-family:'DM Sans',sans-serif; }
.stApp { background: radial-gradient(ellipse at 10% 0%, #07332d 0%, transparent 30%), radial-gradient(ellipse at 90% 10%, #102633 0%, transparent 28%), var(--bg); color:var(--text); }
[data-testid="stHeader"] { background:transparent; }
.block-container { padding-top:1.5rem; padding-bottom:3rem; max-width:1500px; }
section[data-testid="stSidebar"] { background:#071419; border-right:1px solid var(--line); }
section[data-testid="stSidebar"] * { color:var(--text); }
h1,h2,h3 { font-family:'Space Grotesk',sans-serif !important; letter-spacing:-.025em; }
.brand { font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:2.15rem; letter-spacing:.12em; line-height:1.1; }
.brand span { color:var(--green); }
.subtitle { color:var(--muted); margin-top:.35rem; margin-bottom:1.4rem; }
.eyebrow { color:var(--green); font-size:.72rem; font-weight:700; letter-spacing:.17em; text-transform:uppercase; }
.panel { background:linear-gradient(145deg,rgba(13,32,38,.96),rgba(7,20,25,.96)); border:1px solid var(--line); border-radius:16px; padding:1.1rem 1.2rem; margin-bottom:.9rem; box-shadow:0 10px 32px rgba(0,0,0,.12); }
.panel-title { font-family:'Space Grotesk',sans-serif; font-size:1rem; font-weight:600; margin-bottom:.7rem; color:#d8e8ec; }
.drop-note { border:1px dashed #2a5860; border-radius:14px; background:rgba(7,28,32,.6); padding:1rem; text-align:center; color:var(--muted); }
.result { border-radius:15px; padding:1.2rem 1.35rem; border:1px solid; margin:.4rem 0 1rem; }
.result.good { background:linear-gradient(100deg,rgba(0,125,79,.24),rgba(5,37,32,.8)); border-color:#0cbf83; }
.result.bad { background:linear-gradient(100deg,rgba(139,20,43,.28),rgba(38,12,20,.8)); border-color:#f0475e; }
.result.unknown { background:linear-gradient(100deg,rgba(126,91,12,.22),rgba(38,29,9,.8)); border-color:#c99b35; }
.result-label { font-family:'Space Grotesk',sans-serif; font-size:2rem; font-weight:700; line-height:1.1; }
.good .result-label { color:var(--green); } .bad .result-label { color:var(--red); } .unknown .result-label { color:var(--amber); }
.result-copy { color:#c2d4d8; margin-top:.45rem; font-size:.94rem; }
.pill { display:inline-block; border:1px solid var(--line); background:#0a1a20; padding:.42rem .7rem; border-radius:999px; color:#bdd0d5; font-size:.78rem; margin:.12rem .2rem .12rem 0; }
.metric-card { background:rgba(9,25,30,.8); border:1px solid var(--line); padding:.8rem .9rem; border-radius:12px; min-height:82px; }
.metric-label { color:var(--muted); font-size:.78rem; margin-bottom:.35rem; }
.metric-value { font-family:'Space Grotesk',sans-serif; font-size:1.08rem; font-weight:600; overflow-wrap:anywhere; }
.kv { display:flex; justify-content:space-between; gap:1rem; border-bottom:1px solid rgba(32,62,70,.6); padding:.58rem 0; font-size:.86rem; }
.kv:last-child { border-bottom:0; } .kv .key { color:var(--muted); } .kv .value { color:#dcebed; text-align:right; overflow-wrap:anywhere; }
.small-muted { color:var(--muted); font-size:.8rem; }
.stButton>button, .stDownloadButton>button { border-radius:9px; border:1px solid #177d65; background:linear-gradient(90deg,#0b624e,#087e5b); color:white; font-weight:600; }
.stButton>button:hover, .stDownloadButton>button:hover { border-color:var(--green); color:white; }
[data-testid="stFileUploader"] { border:1px dashed #2a5860; border-radius:14px; background:rgba(7,28,32,.45); padding:.4rem; }
[data-testid="stMetric"] { background:rgba(9,25,30,.8); border:1px solid var(--line); border-radius:12px; padding:.8rem; }
[data-testid="stMetricLabel"] { color:var(--muted); }
hr { border-color:var(--line); }
footer { visibility:hidden; }
</style>
""", unsafe_allow_html=True)

# ---------- Analysis helpers ----------
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def identify_file(data: bytes, filename: str) -> dict:
    """Identify common file/container signatures without assuming unsupported files are invalid."""
    head = data[:64]
    ext = Path(filename).suffix.lower()
    detected = "Unknown / unsupported signature"
    expected_exts = set()

    # Container-aware checks that require looking beyond byte zero.
    if len(data) >= 8 and data[4:8] == b"ftyp":
        detected, expected_exts = "MP4 / ISO Base Media container", {".mp4", ".m4v", ".mov", ".3gp", ".m4a"}
    elif head.startswith(b"ID3") or (
        len(data) >= 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0
    ):
        detected, expected_exts = "MP3 / MPEG audio", {".mp3", ".mp2"}
    elif head.startswith(b"RIFF") and data[8:12] == b"WAVE":
        detected, expected_exts = "WAV audio", {".wav"}
    elif head.startswith(b"RIFF") and data[8:12] == b"AVI ":
        detected, expected_exts = "AVI video", {".avi"}
    elif head.startswith(b"RIFF") and data[8:12] == b"WEBP":
        detected, expected_exts = "WebP image", {".webp"}
    elif head.startswith(b"\x1A\x45\xDF\xA3"):
        detected, expected_exts = "Matroska / WebM container", {".mkv", ".webm"}
    elif head.startswith(b"fLaC"):
        detected, expected_exts = "FLAC audio", {".flac"}
    elif head.startswith(b"OggS"):
        detected, expected_exts = "Ogg media container", {".ogg", ".oga", ".ogv", ".opus"}
    elif head.startswith(b"FORM") and data[8:12] in {b"AIFF", b"AIFC"}:
        detected, expected_exts = "AIFF audio", {".aiff", ".aif", ".aifc"}
    elif head.startswith(b"Rar!\x1a\x07"):
        detected, expected_exts = "RAR archive", {".rar"}
    elif head.startswith(b"7z\xBC\xAF\x27\x1C"):
        detected, expected_exts = "7-Zip archive", {".7z"}
    elif head.startswith(b"\x1F\x8B"):
        detected, expected_exts = "GZIP archive", {".gz", ".tgz"}
    elif head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x03\x04"):
        detected, expected_exts = "ZIP-based container (ZIP/DOCX/XLSX and others)", {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt", ".ods", ".odp"}
    else:
        signatures = [
            (b"\x89PNG\r\n\x1a\n", "PNG image", {".png"}),
            (b"\xff\xd8\xff", "JPEG image", {".jpg", ".jpeg"}),
            (b"%PDF-", "PDF document", {".pdf"}),
            (b"GIF87a", "GIF image", {".gif"}), (b"GIF89a", "GIF image", {".gif"}),
            (b"BM", "BMP image", {".bmp"}),
            (b"II*\x00", "TIFF image", {".tif", ".tiff"}),
            (b"MM\x00*", "TIFF image", {".tif", ".tiff"}),
            (b"SQLite format 3\x00", "SQLite database", {".db", ".sqlite", ".sqlite3"}),
            (b"\x7fELF", "ELF executable / binary", {".elf", ".so", ".bin"}),
            (b"MZ", "Windows executable / PE file", {".exe", ".dll", ".sys"}),
            (b"#!", "Script / text file (shebang)", {".sh", ".py", ".pl", ".rb"}),
        ]
        for sig, label, exts in signatures:
            if head.startswith(sig):
                detected, expected_exts = label, exts
                break

    mismatch = bool(expected_exts and ext and ext not in expected_exts)
    return {
        "filename": filename,
        "extension": ext or "(none)",
        "reported_mime_type": mimetypes.guess_type(filename)[0] or "Unknown",
        "detected_signature": detected,
        "signature_extension_mismatch": mismatch,
        "size_bytes": len(data),
        "size_human": f"{len(data):,} bytes ({len(data)/1024:.2f} KiB)",
        "sha256": sha256_bytes(data),
    }

def image_metadata(data: bytes) -> dict:
    result = {}
    try:
        with Image.open(io.BytesIO(data)) as im:
            result.update({"format": im.format, "mode": im.mode, "width_px": im.width, "height_px": im.height, "frame_count": getattr(im, "n_frames", 1)})
            from PIL.ExifTags import TAGS
            exif_values = {}
            for key, value in im.getexif().items():
                name = TAGS.get(key, str(key))
                exif_values[str(name)] = (f"<{len(value)} bytes>" if isinstance(value, bytes) else str(value))[:500]
            result["exif"] = exif_values
            result["embedded_info"] = {str(k): (f"<{len(v)} bytes>" if isinstance(v, bytes) else str(v)[:500]) for k, v in im.info.items()}
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        result["image_parse_note"] = f"Could not parse as a supported image: {type(exc).__name__}"
    return result

def byte_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte; descriptive only, not an AI detector."""
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    import math
    total = len(data)
    return round(-sum((n/total) * math.log2(n/total) for n in counts if n), 4)

def binary_profile(data: bytes) -> dict:
    return {
        "first_32_bytes_hex": data[:32].hex(" "),
        "shannon_entropy_bits_per_byte": byte_entropy(data),
        "zero_byte_percent": round((data.count(b"\x00") / max(1, len(data))) * 100, 3),
        "printable_ascii_percent_sample": round(sum(32 <= b < 127 for b in data[:65536]) / max(1, len(data[:65536])) * 100, 2),
        "note": "Entropy and byte patterns describe file structure; they do not identify AI authorship."
    }

def pdf_metadata(data: bytes) -> dict:
    result = {}
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        result["pages"] = len(reader.pages)
        result["is_encrypted"] = reader.is_encrypted
        result["document_metadata"] = {str(k): str(v)[:1000] for k, v in reader.metadata.items()} if reader.metadata else {}
    except Exception as exc:
        result["pdf_parse_note"] = f"Could not parse PDF metadata: {type(exc).__name__}"
    return result

AI_MARKERS = {
    "Stable Diffusion": [b"stable diffusion", b"stablediffusion", b"automatic1111", b"webui-user.bat", b"comfyui", b"invokeai"],
    "Midjourney": [b"midjourney"],
    "DALL-E / OpenAI": [b"dall-e", b"dall-e", b"openai image", b"images.openai.com"],
    "Adobe Firefly": [b"adobe firefly", b"firefly image"],
    "NovelAI": [b"novelai"],
    "Leonardo AI": [b"leonardo.ai", b"leonardo ai"],
    "Ideogram": [b"ideogram.ai", b"ideogram"],
    "Runway": [b"runwayml", b"runway gen-", b"runway ai"],
    "Pika": [b"pika.art", b"pika labs"],
    "AI-generated label": [b"ai-generated", b"ai generated", b"generated by ai", b"made with ai"],
    "AI provenance metadata": [b"trainedalgorithmicmedia", b"digital sourcetype", b"c2pa", b"content credentials"],
}

def detect_ai_markers(data: bytes, metadata: dict) -> dict:
    """Find explicit AI/provenance strings; this is not a visual AI classifier."""
    haystack = data.lower()
    try:
        meta_bytes = json.dumps(metadata, ensure_ascii=False, default=str).encode("utf-8", errors="ignore").lower()
    except Exception:
        meta_bytes = b""
    combined = haystack + b"\n" + meta_bytes
    found = []
    for family, markers in AI_MARKERS.items():
        matched = [m.decode("utf-8", errors="ignore") for m in markers if m.lower() in combined]
        if matched:
            found.append({"source_or_marker_family": family, "matched_strings": matched[:5]})
    c2pa_present = b"c2pa" in combined or b"content credentials" in combined
    if found:
        status = "AI INDICATORS FOUND"
        color = "red"
        explanation = "One or more AI-related labels or provenance strings were found. Review the matching strings; they can be incomplete, copied, or misleading and do not alone prove how the content was created."
    else:
        status = "NO AI MARKERS FOUND"
        color = "green"
        explanation = "No known AI-related labels or provenance strings were found by this lightweight scan. This does not establish that the file is human-made; markers may be absent or removed."
    return {
        "status": status,
        "color": color,
        "explanation": explanation,
        "matched_indicators": found,
        "c2pa_or_content_credentials_string_found": c2pa_present,
        "method": "Metadata and embedded-string heuristic only; no machine-learning image/video classifier is included.",
    }

def detect_origin_with_sightengine(data: bytes, filename: str, api_user: str, api_secret: str) -> dict:
    response = requests.post(
        "https://api.sightengine.com/1.0/check.json",
        data={"models": "genai", "api_user": api_user.strip(), "api_secret": api_secret.strip()},
        files={"media": (filename, io.BytesIO(data), mimetypes.guess_type(filename)[0] or "application/octet-stream")},
        timeout=45,
    )
    try:
        payload = response.json()
    except ValueError:
        raise RuntimeError(f"Provider returned non-JSON response (HTTP {response.status_code}).")
    if response.status_code >= 400 or payload.get("status") != "success":
        raise RuntimeError(str(payload.get("error", payload.get("message", "Provider error.")))[:400])
    score = payload.get("type", {}).get("ai_generated")
    if not isinstance(score, (int, float)):
        raise RuntimeError("Provider response did not include an AI-generated score.")
    if score >= 0.80:
        verdict, color = "LIKELY AI-GENERATED", "red"
    elif score <= 0.20:
        verdict, color = "LIKELY NOT AI-GENERATED", "green"
    else:
        verdict, color = "INCONCLUSIVE", "amber"
    return {"status": verdict, "color": color, "ai_generated_score_percent": round(float(score)*100, 1),
            "explanation": "Probabilistic estimate only; it can be wrong and is not proof of authorship.",
            "privacy_note": "Image bytes were sent to Sightengine for processing."}


def extract_text_for_origin(data: bytes, filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext in {".txt", ".md", ".csv", ".json", ".html", ".htm", ".rtf", ".py", ".java", ".js", ".css", ".xml"}:
        return data.decode("utf-8", errors="ignore")[:150000]
    if ext == ".pdf":
        try:
            reader = PdfReader(io.BytesIO(data), strict=False)
            return "\n".join((page.extract_text() or "") for page in reader.pages)[:150000]
        except Exception:
            return ""
    if ext == ".docx":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                root = ET.fromstring(zf.read("word/document.xml"))
            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            return "\n".join("".join(node.itertext()) for node in root.findall(".//w:p", ns))[:150000]
        except Exception:
            return ""
    return ""

def _origin_score_result(score: float, label: str, provider: str, details: str = "") -> dict:
    score = max(0.0, min(1.0, float(score)))
    if score >= 0.80:
        status, color = f"LIKELY AI-{label}", "red"
    elif score <= 0.20:
        status, color = f"LIKELY NOT AI-{label}", "green"
    else:
        status, color = "INCONCLUSIVE", "amber"
    return {"status": status, "color": color, "score_percent": round(score * 100, 1),
            "provider": provider,
            "explanation": "Probabilistic estimate only. False positives and false negatives are possible; this does not prove authorship.",
            "details": details}

def run_sightengine_media(data: bytes, filename: str, api_user: str, api_secret: str, kind: str) -> dict:
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    if kind == "image":
        endpoint, field, models = "https://api.sightengine.com/1.0/check.json", "media", "genai"
    elif kind == "video":
        endpoint, field, models = "https://api.sightengine.com/1.0/video/check-sync.json", "media", "genai"
    else:
        endpoint, field, models = "https://api.sightengine.com/1.0/audio/check.json", "audio", "ai_speech,ai_music"
    r = requests.post(endpoint, data={"models": models, "api_user": api_user.strip(), "api_secret": api_secret.strip()},
                      files={field: (filename, io.BytesIO(data), mime)}, timeout=90)
    try:
        payload = r.json()
    except ValueError:
        raise RuntimeError(f"Provider returned non-JSON response (HTTP {r.status_code}).")
    if r.status_code >= 400 or payload.get("status") != "success":
        raise RuntimeError(str(payload.get("error", payload.get("message", f"Provider HTTP {r.status_code}")))[:400])
    typ = payload.get("type", {})
    if kind == "audio":
        candidates = [(float(typ[k]), k) for k in ("ai_speech", "ai_music") if isinstance(typ.get(k), (int, float))]
        if not candidates:
            raise RuntimeError("No audio scores returned; this model may not be enabled for your account.")
        score, model = max(candidates)
        return _origin_score_result(score, "GENERATED AUDIO", "Sightengine", f"Highest returned audio score: {model}={score:.3f}; all scores: {typ}")
    if kind == "video":
        frames = payload.get("data", {}).get("frames", [])
        scores = [f.get("type", {}).get("ai_generated") for f in frames]
        scores = [float(s) for s in scores if isinstance(s, (int, float))]
        if not scores and isinstance(typ.get("ai_generated"), (int, float)):
            scores = [float(typ["ai_generated"])]
        if not scores:
            raise RuntimeError("No video frame scores returned. Try a short clip or check account access.")
        result = _origin_score_result(sum(scores)/len(scores), "GENERATED VIDEO", "Sightengine", f"Average of {len(scores)} analyzed frame(s).")
        result["frame_scores_percent"] = [round(s*100, 1) for s in scores[:100]]
        return result
    score = typ.get("ai_generated")
    if not isinstance(score, (int, float)):
        raise RuntimeError("No AI-generated score returned.")
    generators = typ.get("ai_generators", {})
    return _origin_score_result(score, "GENERATED IMAGE", "Sightengine", f"Generator scores: {generators}")

def _normalized_provider_result(provider: str, score: float, model: str, details=None, raw=None) -> dict:
    score = max(0.0, min(1.0, float(score)))
    return {
        "provider": provider,
        "model": model,
        "ai_score_percent": round(score * 100, 2),
        "non_ai_complement_percent": round((1.0 - score) * 100, 2),
        "interpretation": "LIKELY AI" if score >= 0.80 else "LIKELY NON-AI" if score <= 0.20 else "UNCERTAIN",
        "details": details or {},
        "raw_response": raw or {},
    }

def _find_class_score(classes, labels):
    if not isinstance(classes, list):
        return None
    for item in classes:
        if not isinstance(item, dict):
            continue
        label = str(item.get("class", item.get("label", ""))).lower()
        if label in labels:
            value = item.get("score", item.get("confidence"))
            if isinstance(value, (int, float)):
                return float(value)
    return None

def run_sightengine_image(data: bytes, filename: str, api_user: str, api_secret: str) -> dict:
    payload = requests.post(
        "https://api.sightengine.com/1.0/check.json",
        data={"models": "genai", "api_user": api_user.strip(), "api_secret": api_secret.strip()},
        files={"media": (filename, io.BytesIO(data), mimetypes.guess_type(filename)[0] or "application/octet-stream")},
        timeout=75,
    )
    try:
        body = payload.json()
    except ValueError:
        raise RuntimeError(f"Sightengine returned non-JSON (HTTP {payload.status_code}).")
    if payload.status_code >= 400 or body.get("status") != "success":
        raise RuntimeError(str(body.get("error", body.get("message", f"HTTP {payload.status_code}")))[:350])
    typ = body.get("type", {})
    score = typ.get("ai_generated") if isinstance(typ, dict) else None
    if not isinstance(score, (int, float)):
        raise RuntimeError("Sightengine response did not contain type.ai_generated.")
    generators = typ.get("ai_generators", {}) if isinstance(typ, dict) else {}
    return _normalized_provider_result("Sightengine", score, "genai", {"generator_scores": generators, "method": "pixel-content model; metadata is not used for this score"}, body)

def run_aiornot_image(data: bytes, filename: str, api_key: str) -> dict:
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    response = requests.post(
        "https://api.aiornot.com/v2/image/sync",
        headers={"Authorization": f"Bearer {api_key.strip()}", "accept": "application/json"},
        files={"image": (filename, io.BytesIO(data), mime)},
        params=[("only", "ai_generated")],
        timeout=75,
    )
    try:
        body = response.json()
    except ValueError:
        raise RuntimeError(f"AI or Not returned non-JSON (HTTP {response.status_code}).")
    if response.status_code >= 400:
        raise RuntimeError(str(body.get("message", body.get("error", f"HTTP {response.status_code}")))[:350])
    report = body.get("report", {}) if isinstance(body, dict) else {}
    ai_block = report.get("ai_generated", {}) if isinstance(report, dict) else {}
    ai_info = ai_block.get("ai", {}) if isinstance(ai_block, dict) else {}
    score = ai_info.get("confidence") if isinstance(ai_info, dict) else None
    if not isinstance(score, (int, float)):
        verdict = str(ai_block.get("verdict", "")).lower() if isinstance(ai_block, dict) else ""
        if verdict in {"ai", "likely_ai", "likely ai"}:
            score = 0.9
        elif verdict in {"human", "not_ai", "not ai"}:
            score = 0.1
        else:
            raise RuntimeError("AI or Not response did not contain a usable AI confidence score.")
    gen = ai_block.get("generator", {}) if isinstance(ai_block, dict) else {}
    return _normalized_provider_result("AI or Not", score, "image AI detector", {"verdict": ai_block.get("verdict"), "generator_scores": gen, "processing_status": report.get("meta", {}).get("processing_status", {})}, body)

def run_wasitaigenerated_image(data: bytes, filename: str, api_key: str) -> dict:
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    response = requests.post(
        "https://www.wasitaigenerated.com/api/v1/detect/image",
        headers={"Authorization": f"Bearer {api_key.strip()}"},
        files={"file": (filename, io.BytesIO(data), mime)},
        timeout=120,
    )
    try:
        body = response.json()
    except ValueError:
        raise RuntimeError(f"WasItAIGenerated returned non-JSON (HTTP {response.status_code}).")
    if response.status_code >= 400:
        msg = body.get("message", body.get("error", f"HTTP {response.status_code}"))
        if response.status_code == 402:
            msg = f"Insufficient API credits: {msg}"
        raise RuntimeError(str(msg)[:350])
    score = body.get("confidence")
    if not isinstance(score, (int, float)):
        detailed = body.get("detailed", {})
        scores = detailed.get("scores", {}) if isinstance(detailed, dict) else {}
        score = scores.get("ai")
        if isinstance(score, (int, float)) and score > 1:
            score = float(score) / 100.0
    if not isinstance(score, (int, float)):
        raise RuntimeError("WasItAIGenerated response did not contain confidence or detailed.scores.ai.")
    c2pa = body.get("c2pa") if isinstance(body.get("c2pa"), dict) else {}
    details = {
        "api_model": body.get("detailed", {}).get("model") if isinstance(body.get("detailed"), dict) else None,
        "verified_ai_provenance": bool(body.get("verified")),
        "c2pa": c2pa,
        "provenance": body.get("provenance", {}),
        "patterns": body.get("patterns", []),
        "reasoning": body.get("analysis", {}).get("reasoning") if isinstance(body.get("analysis"), dict) else None,
        "credits_charged": body.get("creditsCharged", 300),
    }
    if body.get("verified") is True and c2pa.get("signatureValid") is True and c2pa.get("isAI") is True:
        details["cryptographic_provenance_note"] = "Provider reports a valid C2PA signature whose manifest declares AI-generated content. Check issuer trust separately; signature validity alone is not the same as a trusted issuer."
    elif c2pa.get("signatureValid") is True and c2pa.get("sourceType") == "digitalCapture":
        details["cryptographic_provenance_note"] = "Provider reports a valid C2PA manifest with digitalCapture source type. Review issuer/trust status and original file before drawing conclusions."
    return _normalized_provider_result("WasItAIGenerated", score, str(details.get("api_model") or "image detector"), details, body)

def run_hive_image(data: bytes, filename: str, api_key: str) -> dict:
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    response = requests.post(
        "https://api.thehive.ai/api/v2/task/sync",
        headers={"Authorization": f"Token {api_key.strip()}", "accept": "application/json"},
        files={"media": (filename, io.BytesIO(data), mime)},
        timeout=90,
    )
    try:
        body = response.json()
    except ValueError:
        raise RuntimeError(f"Hive returned non-JSON (HTTP {response.status_code}).")
    if response.status_code >= 400:
        raise RuntimeError(str(body.get("message", body.get("error", f"HTTP {response.status_code}")))[:350])
    statuses = body.get("status", []) if isinstance(body, dict) else []
    response_obj = statuses[0].get("response", {}) if statuses and isinstance(statuses[0], dict) else {}
    outputs = response_obj.get("output", []) if isinstance(response_obj, dict) else []
    classes = outputs[0].get("classes", []) if outputs and isinstance(outputs[0], dict) else []
    score = _find_class_score(classes, {"ai_generated"})
    if score is None:
        not_ai = _find_class_score(classes, {"not_ai_generated"})
        if not_ai is not None:
            score = 1.0 - not_ai
    if score is None:
        raise RuntimeError("Hive response did not include ai_generated/not_ai_generated classes. Confirm this is an AI-art detection project key.")
    generator_scores = [x for x in classes if isinstance(x, dict) and x.get("class") not in {"ai_generated", "not_ai_generated", "deepfake"}]
    generator_scores.sort(key=lambda x: float(x.get("score", 0) or 0), reverse=True)
    return _normalized_provider_result("Hive", score, "AI art and deepfake detection", {"top_generator_classes": generator_scores[:8]}, body)


@st.cache_resource(show_spinner=False)
def _load_local_hf_detector():
    """Load an open model locally; weights cache on this Mac after first download."""
    from transformers import pipeline
    return pipeline(
        "image-classification",
        model="capcheck/ai-image-detection",
        device=-1,
    )

def run_local_free_image_detector(data: bytes, filename: str) -> dict:
    """Run a free, open Hugging Face image classifier locally (no API key)."""
    try:
        from PIL import Image, ImageOps
        detector = _load_local_hf_detector()
        with Image.open(io.BytesIO(data)) as raw_image:
            image = ImageOps.exif_transpose(raw_image).convert("RGB")
        predictions = detector(image, top_k=None)
        if isinstance(predictions, dict):
            predictions = [predictions]
        scores = {str(item.get("label", "")).strip().lower(): float(item.get("score", 0)) for item in predictions if isinstance(item, dict)}
        ai_score = None
        for label, score in scores.items():
            if any(word in label for word in ("fake", "ai", "artificial", "synthetic", "generated")):
                ai_score = score if ai_score is None else max(ai_score, score)
        if ai_score is None:
            real_scores = [score for label, score in scores.items() if "real" in label or "human" in label or "authentic" in label]
            if real_scores:
                ai_score = 1.0 - max(real_scores)
        if ai_score is None:
            raise RuntimeError(f"Could not map model labels to AI/real classes: {list(scores.keys())}")
        return _normalized_provider_result(
            "Local Hugging Face (free)", ai_score, "capcheck/ai-image-detection · ViT",
            {"execution": "local on this computer", "api_key_required": False, "raw_label_scores": scores,
             "model_note": "Trained primarily on CIFAKE / older generators; modern generators may be missed."},
            {"predictions": [{"label": k, "score": v} for k, v in scores.items()]},
        )
    except ImportError as exc:
        raise RuntimeError("Local model packages are not installed. Run: python3 -m pip install -r requirements-local-model.txt") from exc

def run_image_ensemble(data: bytes, filename: str, credentials: dict) -> dict:
    providers = []
    errors = []
    calls = [
        ("Sightengine", bool(credentials.get("sightengine_user") and credentials.get("sightengine_secret")), lambda: run_sightengine_image(data, filename, credentials["sightengine_user"], credentials["sightengine_secret"])),
        ("AI or Not", bool(credentials.get("aiornot_key")), lambda: run_aiornot_image(data, filename, credentials["aiornot_key"])),
        ("WasItAIGenerated", bool(credentials.get("wasitai_key")), lambda: run_wasitaigenerated_image(data, filename, credentials["wasitai_key"])),
        ("Hive", bool(credentials.get("hive_key")), lambda: run_hive_image(data, filename, credentials["hive_key"])),
        ("Local Hugging Face (free)", bool(credentials.get("use_local_model")), lambda: run_local_free_image_detector(data, filename)),
    ]
    for name, configured, call in calls:
        if not configured:
            errors.append({"provider": name, "status": "NOT CONFIGURED", "message": "Add this provider's key to .env to include it in the ensemble."})
            continue
        try:
            providers.append(call())
        except Exception as exc:
            errors.append({"provider": name, "status": "FAILED", "message": str(exc)[:400]})
    scores = [p["ai_score_percent"] for p in providers]
    if len(scores) >= 2:
        mean_score = round(sum(scores) / len(scores), 2)
        sorted_scores = sorted(scores)
        n = len(sorted_scores)
        median_score = round((sorted_scores[n//2] if n % 2 else (sorted_scores[n//2-1] + sorted_scores[n//2]) / 2), 2)
        spread = round(max(scores) - min(scores), 2)
        if mean_score >= 80 and sum(s >= 80 for s in scores) >= (len(scores)//2 + 1):
            consensus = "MULTI-ENGINE SIGNAL: LIKELY AI-GENERATED"
        elif mean_score <= 20 and sum(s <= 20 for s in scores) >= (len(scores)//2 + 1):
            consensus = "MULTI-ENGINE SIGNAL: LIKELY NON-AI"
        else:
            consensus = "MIXED / INCONCLUSIVE — HUMAN REVIEW"
        if spread >= 30:
            consensus += " (HIGH MODEL DISAGREEMENT)"
        aggregate = {
            "mean_ai_likelihood_percent": mean_score,
            "complementary_non_ai_score_percent": round(100 - mean_score, 2),
            "median_ai_score_percent": median_score,
            "provider_score_spread_percentage_points": spread,
            "consensus": consensus,
            "providers_counted": len(scores),
            "warning": "The mean is a simple ensemble summary, not a calibrated real-world probability. Models may share biases and their scores are not guaranteed to be independent or comparable. The complementary score does not prove the image is real or human-made."
        }
    elif len(scores) == 1:
        aggregate = {
            "mean_ai_likelihood_percent": scores[0],
            "complementary_non_ai_score_percent": round(100 - scores[0], 2),
            "median_ai_score_percent": scores[0],
            "provider_score_spread_percentage_points": 0,
            "consensus": "SINGLE ENGINE ONLY — NOT AN ENSEMBLE",
            "providers_counted": 1,
            "warning": "Only one detector returned a score. No multi-provider consensus is available; the complementary score does not prove the image is real."
        }
    else:
        aggregate = {
            "mean_ai_likelihood_percent": None,
            "complementary_non_ai_score_percent": None,
            "median_ai_score_percent": None,
            "provider_score_spread_percentage_points": None,
            "consensus": "NO DETECTOR RESULT — CONFIGURE AT LEAST ONE WORKING PROVIDER",
            "providers_counted": 0,
            "warning": "No AI-image detector returned a usable result."
        }
    return {
        "analysis_type": "multi-engine AI-generated image detection",
        "providers": providers,
        "provider_issues": errors,
        "aggregate": aggregate,
        "generator_candidates": _collect_generator_candidates(providers),
        "evidence_basis": {
            "pixel_model_scores": "Sightengine, AI or Not, WasItAIGenerated, optional Hive, and/or the local Hugging Face model; only providers that return a score are counted.",
            "metadata_and_provenance": "Local EXIF/XMP/embedded metadata plus C2PA/provenance fields returned by providers when present. Metadata can be absent or altered.",
            "binary_structure": "SHA-256, file signature, extension/MIME agreement, entropy and byte profile. These describe the exact file and its structure; they are not authorship detectors.",
        },
        "limitations": "The local model is free after download and sends no image to a provider. A probabilistic detector cannot certify a person, camera, place, or event. Editing, screenshots, compression, unknown generators and domain shift can affect results. Preserve the original file and corroborate with source records."
    }

def _collect_generator_candidates(provider_results):
    candidates = []
    for provider in provider_results:
        details = provider.get("details", {})
        gen = details.get("generator_scores", {})
        if isinstance(gen, dict):
            for label, value in gen.items():
                if isinstance(value, (int, float)):
                    candidates.append({"provider": provider["provider"], "generator": label, "score_percent": round(float(value) * 100 if value <= 1 else float(value), 2)})
        for item in details.get("top_generator_classes", []) if isinstance(details.get("top_generator_classes"), list) else []:
            if isinstance(item, dict) and isinstance(item.get("score"), (int, float)):
                candidates.append({"provider": provider["provider"], "generator": item.get("class", "unknown"), "score_percent": round(float(item["score"]) * 100, 2)})
        c2pa = details.get("c2pa", {})
        if isinstance(c2pa, dict) and (c2pa.get("generator") or c2pa.get("vendor")):
            candidates.append({"provider": provider["provider"], "generator": c2pa.get("generator") or c2pa.get("vendor"), "score_percent": None, "basis": "C2PA manifest claim"})
    candidates.sort(key=lambda x: x.get("score_percent") or 0, reverse=True)
    return candidates[:20]

def run_gptzero_text(text_content: str, api_key: str) -> dict:
    if len(text_content.strip()) < 100:
        raise RuntimeError("Not enough extractable text for a useful text-origin check (at least ~100 characters needed).")
    r = requests.post("https://api.gptzero.me/v2/predict/text",
                      headers={"x-api-key": api_key.strip(), "Content-Type": "application/json"},
                      json={"document": text_content[:150000]}, timeout=60)
    try:
        payload = r.json()
    except ValueError:
        raise RuntimeError(f"GPTZero returned non-JSON response (HTTP {r.status_code}).")
    if r.status_code >= 400:
        raise RuntimeError(str(payload.get("message", payload.get("error", f"GPTZero HTTP {r.status_code}")))[:400])
    docs = payload.get("documents") or payload.get("results") or []
    doc = docs[0] if docs and isinstance(docs[0], dict) else payload
    probability = doc.get("completely_generated_prob", doc.get("ai_probability", doc.get("probability")))
    classification = str(doc.get("class", doc.get("result", ""))).lower()
    if isinstance(probability, (int, float)):
        score = float(probability)
    elif "ai" in classification:
        score = 0.9
    elif "human" in classification or "not_ai" in classification:
        score = 0.1
    else:
        raise RuntimeError("Could not interpret GPTZero's response schema. Review the API response/docs.")
    return _origin_score_result(score, "WRITTEN", "GPTZero", f"Text classification: {classification or 'score-based'}")

def analyze(data: bytes, filename: str) -> dict:
    result = identify_file(data, filename)
    result["analysis_time_utc"] = datetime.now(timezone.utc).isoformat()
    result["metadata"] = {}
    result["binary_profile"] = binary_profile(data)
    if result["detected_signature"] in {"PNG image", "JPEG image", "GIF image", "BMP image", "TIFF image", "WebP image"}:
        result["metadata"] = image_metadata(data)
    elif result["detected_signature"] == "PDF document":
        result["metadata"] = pdf_metadata(data)
    else:
        result["metadata"]["note"] = "Signature recognized only when supported; deep parsing is not implemented for every file type."
    # AI marker scan is separate from structural triage and is not a visual AI classifier.
    result["ai_marker_scan"] = detect_ai_markers(data, result["metadata"])
    # A cautious, structural triage label—not a proof of authenticity.
    parse_failed = any(k.endswith("_parse_note") for k in result["metadata"])
    if result["signature_extension_mismatch"] or parse_failed:
        result["triage_status"] = "SUSPICIOUS INDICATOR"
        result["triage_color"] = "red"
        result["triage_explanation"] = "A file extension/signature mismatch or parsing issue needs review. This does not prove the file is fake or malicious."
    elif result["detected_signature"] != "Unknown / unsupported signature":
        result["triage_status"] = "NO OBVIOUS FLAGS"
        result["triage_color"] = "green"
        result["triage_explanation"] = "The file signature is recognized and no basic structural mismatch was detected. This does not prove the content is genuine or not AI-generated."
    else:
        result["triage_status"] = "UNVERIFIED"
        result["triage_color"] = "amber"
        result["triage_explanation"] = "This file type is not validated by the current MVP. Lack of recognition does not mean the file is fake."
    result["interpretation"] = [
        "SHA-256 identifies these exact bytes; it does not reveal the file's complete history.",
        "Embedded dates and metadata can be missing, edited, or inaccurate.",
        "The AI marker scan looks for known labels and embedded provenance strings only; it is not a visual AI classifier and cannot prove real/fake status.",
        "A file alone normally cannot reveal its creator account, phone number, or IP address.",
    ]
    return result

def kv(label, value):
    st.markdown(f'<div class="kv"><span class="key">{label}</span><span class="value">{value}</span></div>', unsafe_allow_html=True)


def advanced_image_forensics(data: bytes, filename: str) -> dict:
    """Local image characteristics and optional JPEG ELA; descriptive evidence, not authorship proof."""
    result = {"filename": filename, "ela_available": False, "notes": []}
    try:
        with Image.open(io.BytesIO(data)) as im:
            result.update({
                "format_reported_by_decoder": im.format,
                "width_px": im.width,
                "height_px": im.height,
                "pixel_count": int(im.width * im.height),
                "mode": im.mode,
                "frame_count": int(getattr(im, "n_frames", 1)),
                "has_alpha_channel": "A" in im.getbands(),
                "embedded_icc_profile": bool(im.info.get("icc_profile")),
                "embedded_exif": bool(im.info.get("exif")),
                "embedded_comment": bool(im.info.get("comment")),
            })
            try:
                exif = im.getexif()
                exif_labels = {
                    271: "Make", 272: "Model", 306: "DateTime", 315: "Artist",
                     305: "Software", 33432: "Copyright",
                    36867: "DateTimeOriginal", 42036: "LensModel",
                }
                selected = {}
                for tag_id, val in exif.items():
                    label = exif_labels.get(tag_id)
                    if label and isinstance(val, (str, int, float)):
                        selected[label] = str(val)[:200]
                result["selected_exif_fields"] = selected
            except Exception as e:
                result["exif_read_note"] = str(e)[:180]
            if im.format == "JPEG":
                original = im.convert("RGB")
                recompressed = io.BytesIO()
                original.save(recompressed, format="JPEG", quality=90, optimize=False)
                rec = Image.open(io.BytesIO(recompressed.getvalue())).convert("RGB")
                from PIL import ImageChops, ImageStat, ImageEnhance
                diff = ImageChops.difference(original, rec)
                stat = ImageStat.Stat(diff)
                result["ela_available"] = True
                result["ela_recompression_quality"] = 90
                result["ela_mean_channel_difference"] = round(sum(stat.mean) / len(stat.mean), 4)
                result["ela_max_channel_difference"] = round(max(stat.extrema[i][1] for i in range(3)), 4)
                heat = ImageEnhance.Contrast(diff).enhance(4.0)
                heat = heat.resize((min(900, heat.width), max(1, int(heat.height * min(900, heat.width) / heat.width))))
                buf = io.BytesIO()
                heat.save(buf, format="PNG")
                result["ela_preview_png_base64"] = __import__("base64").b64encode(buf.getvalue()).decode("ascii")
                result["notes"].append("ELA highlights differences after JPEG recompression; editing, quality, resizing and normal processing can all affect it. It does not identify AI authorship.")
            else:
                result["notes"].append("ELA preview is only generated for JPEG input. Other formats still receive metadata and structural checks.")
            result["notes"].append("EXIF fields can be removed, edited or copied. Their presence or absence is not proof of genuine or AI-generated content.")
    except Exception as e:
        result["error"] = str(e)[:300]
    return result

# ---------- Header / sidebar ----------
st.markdown('<div class="brand">TRACE<span>WEAVE</span></div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">DIGITAL FORENSICS STUDIO &nbsp;·&nbsp; File integrity, metadata and binary triage</div>', unsafe_allow_html=True)
with st.sidebar:
    st.markdown('<div class="eyebrow">Investigation workspace</div>', unsafe_allow_html=True)
    st.markdown("## 🧵 TRACEWEAVE")
    st.caption("Advanced • Multi-engine image forensics")
    st.markdown("---")
    st.markdown("**TOOLS**")
    st.markdown("🟢 &nbsp; File analysis  \n🔗 &nbsp; Compare files  \n🧾 &nbsp; Evidence report")
    st.markdown("---")
    st.markdown("**SUPPORTED INSPECTION**")
    st.markdown("- PNG, JPG/JPEG, GIF, BMP, TIFF, WebP images\n- Up to 4 optional API providers plus 1 free local model\n- EXIF/embedded metadata and C2PA provenance when available\n- SHA-256, magic bytes, binary entropy and signature checks\n- MP3, MP4/MOV, WAV, AVI, FLAC, Ogg, WebM/MKV checks\n- PDF and ZIP-based document/archive signatures\n- Byte-level comparison")
    st.markdown("---")
    st.caption("Upload limit: 25 MB per file. All file types can be selected; detailed parsing varies by format. Files are analyzed in memory by this app; avoid uploading sensitive files to an untrusted deployment.")

analyze_tab, compare_tab = st.tabs(["⌕  FILE ANALYSIS", "⇄  COMPARE FILES"])

with analyze_tab:
    left, right = st.columns([1.08, .92], gap="large")
    with left:
        st.markdown('<div class="panel"><div class="eyebrow">01 / Evidence intake</div><div class="panel-title">Upload evidence file</div><div class="small-muted">Choose any file type — images, audio, video, PDFs, archives, documents, or binaries — for a structural first-pass check.</div></div>', unsafe_allow_html=True)
        uploaded = st.file_uploader("Drop a file here or browse", key="single", label_visibility="collapsed")
        st.markdown('<div class="small-muted">All file extensions can be uploaded. Images and PDFs receive deeper metadata parsing; audio, video, archives, documents, and binaries receive signature-level checks where recognizable.</div>', unsafe_allow_html=True)
    with right:
        st.markdown('<div class="panel"><div class="eyebrow">02 / Triage guide</div><div class="panel-title">Status legend</div><span class="pill">🟢 No obvious flags</span><span class="pill">🔴 Suspicious indicator</span><span class="pill">🟡 Unverified</span><p class="small-muted" style="margin-top:.6rem">These are structural indicators—not a reliable real/fake or AI-generated classifier.</p></div>', unsafe_allow_html=True)

    if uploaded:
        data = uploaded.getvalue()
        if len(data) > MAX_BYTES:
            st.error("This file exceeds the 25 MB limit. Choose a smaller file.")
        else:
            report = analyze(data, uploaded.name)
            ai = report["ai_marker_scan"]
            ext_forensics = Path(uploaded.name).suffix.lower()
            if ext_forensics in {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff"}:
                local_img_forensics = advanced_image_forensics(data, uploaded.name)
                # Exclude the preview payload from the default JSON object; it is offered separately below.
                report["advanced_image_forensics"] = {k: v for k, v in local_img_forensics.items() if k != "ela_preview_png_base64"}
                with st.expander("Advanced local image forensics • metadata, dimensions & JPEG ELA", expanded=False):
                    if local_img_forensics.get("error"):
                        st.warning(local_img_forensics["error"])
                    else:
                        keys = ["format_reported_by_decoder", "width_px", "height_px", "pixel_count", "mode", "frame_count", "has_alpha_channel", "embedded_icc_profile", "embedded_exif"]
                        st.dataframe([{"Property": k, "Value": local_img_forensics.get(k)} for k in keys], use_container_width=True, hide_index=True)
                        if local_img_forensics.get("selected_exif_fields"):
                            st.markdown("**Selected EXIF fields**")
                            st.json(local_img_forensics["selected_exif_fields"], expanded=True)
                        if local_img_forensics.get("ela_available"):
                            st.markdown("**JPEG Error Level Analysis (ELA) preview**")
                            st.image(__import__("base64").b64decode(local_img_forensics["ela_preview_png_base64"]), caption="Contrast-enhanced recompression difference — review clue only, not an AI detector")
                            st.metric("Mean channel difference", local_img_forensics["ela_mean_channel_difference"])
                            st.download_button("Download ELA preview", __import__("base64").b64decode(local_img_forensics["ela_preview_png_base64"]), file_name=f"{Path(uploaded.name).stem}_ela_preview.png", mime="image/png")
                        for note in local_img_forensics.get("notes", []):
                            st.caption(note)

            st.markdown('<div class="panel"><div class="eyebrow">AI vs Human origin</div><div class="panel-title">Multi-engine image origin detection</div><div class="small-muted">Images can be checked with a free local Hugging Face model plus up to four optional external API providers. Only enabled/configured engines run. A simple average is an estimate, not a calibrated probability or proof. Each remote provider receives the image only when its scan is run.</div></div>', unsafe_allow_html=True)
            ext = Path(uploaded.name).suffix.lower()
            image_exts = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff"}
            video_exts = {".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm", ".3gp"}
            audio_exts = {".mp3", ".wav", ".flac", ".ogg", ".opus", ".m4a", ".aac", ".aiff"}
            text_exts = {".pdf", ".docx", ".txt", ".md", ".csv", ".json", ".html", ".htm", ".rtf", ".py", ".java", ".js", ".css", ".xml"}
            kind = "image" if ext in image_exts else "video" if ext in video_exts else "audio" if ext in audio_exts else "text" if ext in text_exts else "unsupported"
            with st.expander("API setup and run origin scan", expanded=True):
                if kind == "image":
                    st.caption("Free-first setup: the local Hugging Face model needs no API key and runs on this Mac after its model download. Optional external APIs can have quotas, credit limits or charges; check provider terms before enabling them.")
                    st.markdown("**Provider configuration**")
                    env_keys = {
                        "Sightengine": bool(os.getenv("SIGHTENGINE_API_USER") and os.getenv("SIGHTENGINE_API_SECRET")),
                        "AI or Not": bool(os.getenv("AIORNOT_API_KEY")),
                        "WasItAIGenerated": bool(os.getenv("WASITAI_API_KEY")),
                        "Hive (optional)": bool(os.getenv("HIVE_API_KEY")),
                    }
                    status_cols = st.columns(4)
                    for col, (provider_name, is_ready) in zip(status_cols, env_keys.items()):
                        with col:
                            st.metric(provider_name, "Ready" if is_ready else "Key missing")
                    st.caption("Keys are read from the local .env file. They are not displayed in this screen. To use only free local detection, enable the local model below; leave API keys unset.")
                    use_local_model = st.checkbox("Include free local Hugging Face model (downloads model weights on first run)", value=True, key="use_local_hf_model")
                    if st.button("Run multi-engine image scan", key="run_multimedia_origin"):
                        if len(data) > 10 * 1024 * 1024 and (os.getenv("WASITAI_API_KEY") or os.getenv("AIORNOT_API_KEY")):
                            st.warning("AI or Not / WasItAIGenerated have 10 MB limits for the documented image upload routes. Oversized files may fail at those providers; other configured routes will still be attempted.")
                        creds = {
                            "sightengine_user": os.getenv("SIGHTENGINE_API_USER", ""),
                            "sightengine_secret": os.getenv("SIGHTENGINE_API_SECRET", ""),
                            "aiornot_key": os.getenv("AIORNOT_API_KEY", ""),
                            "wasitai_key": os.getenv("WASITAI_API_KEY", ""),
                            "hive_key": os.getenv("HIVE_API_KEY", ""),
                            "use_local_model": use_local_model,
                        }
                        with st.spinner("Running enabled image detectors. The local model runs on this Mac; external providers may consume quota/credits."):
                            ensemble_result = run_image_ensemble(data, uploaded.name, creds)
                            st.session_state["origin_" + report["sha256"]] = ensemble_result
                            report["image_origin_ensemble"] = ensemble_result
                elif kind in {"video", "audio"}:
                    st.caption(f"Detector route: {kind.upper()} via Sightengine. Relevant model access and usage limits depend on your account.")
                    api_user = os.getenv("SIGHTENGINE_API_USER", "")
                    api_secret = os.getenv("SIGHTENGINE_API_SECRET", "")
                    if st.button("Run AI-origin scan", key="run_multimedia_origin"):
                        if not api_user or not api_secret:
                            st.warning("Add SIGHTENGINE_API_USER and SIGHTENGINE_API_SECRET to .env first.")
                        elif kind == "audio" and len(data) > 20 * 1024 * 1024:
                            st.error("Audio detector supports up to 20 MB according to the provider documentation.")
                        else:
                            with st.spinner(f"Running {kind} origin analysis..."):
                                try:
                                    st.session_state["origin_" + report["sha256"]] = run_sightengine_media(data, uploaded.name, api_user, api_secret, kind)
                                except Exception as exc:
                                    st.session_state["origin_" + report["sha256"]] = {"status": "DETECTOR ERROR", "color": "amber", "explanation": str(exc)}
                elif kind == "text":
                    st.caption("PDF text is extracted before checking. This checks writing only, not images embedded in the PDF.")
                    gpt_key = st.text_input("GPTZero API Key", value=os.getenv("GPTZERO_API_KEY", ""), type="password", key="gptzero_key")
                    if st.button("Run AI-text scan", key="run_text_origin"):
                        extracted = extract_text_for_origin(data, uploaded.name)
                        if not gpt_key.strip():
                            st.warning("Enter your GPTZero API key first.")
                        elif not extracted.strip():
                            st.error("No extractable text found in this file.")
                        else:
                            with st.spinner("Checking extracted text..."):
                                try:
                                    st.session_state["origin_" + report["sha256"]] = run_gptzero_text(extracted, gpt_key)
                                except Exception as exc:
                                    st.session_state["origin_" + report["sha256"]] = {"status": "DETECTOR ERROR", "color": "amber", "explanation": str(exc)}
                else:
                    st.warning("No suitable origin detector is configured for this file type. Fingerprints and metadata do not prove human or AI authorship.")
            origin = st.session_state.get("origin_" + report["sha256"])
            if origin:
                if isinstance(origin, dict) and origin.get("analysis_type") == "multi-engine AI-generated image detection":
                    agg = origin.get("aggregate", {})
                    st.markdown('<div class="eyebrow">Multi-engine AI assessment</div>', unsafe_allow_html=True)
                    st.subheader(agg.get("consensus", "No consensus"))
                    score_val = agg.get("mean_ai_likelihood_percent")
                    mcols = st.columns(4)
                    with mcols[0]: st.metric("Ensemble AI-likelihood mean", f"{score_val:.1f}%" if isinstance(score_val, (int, float)) else "N/A")
                    with mcols[1]: st.metric("Complementary non-AI score", f"{agg['complementary_non_ai_score_percent']:.1f}%" if isinstance(agg.get("complementary_non_ai_score_percent"), (int, float)) else "N/A")
                    with mcols[2]: st.metric("Successful engines", f"{agg.get('providers_counted', 0)} / 5")
                    with mcols[3]: st.metric("Score spread", f"{agg['provider_score_spread_percentage_points']:.1f} pp" if isinstance(agg.get("provider_score_spread_percentage_points"), (int, float)) else "N/A")
                    st.warning(agg.get("warning", "Detector outputs are estimates."))
                    provider_rows = [{"Provider": x.get("provider"), "Model": x.get("model"), "AI likelihood": f"{x.get('ai_score_percent', 0):.2f}%", "Complement": f"{x.get('non_ai_complement_percent', 0):.2f}%", "Provider interpretation": x.get("interpretation")} for x in origin.get("providers", [])]
                    if provider_rows:
                        st.markdown("**Provider-by-provider results**")
                        st.dataframe(provider_rows, use_container_width=True, hide_index=True)
                        st.bar_chart({row["Provider"]: float(row["AI likelihood"].rstrip("%")) for row in provider_rows})
                    if origin.get("generator_candidates"):
                        st.markdown("**Possible generator / source indicators returned by providers**")
                        st.dataframe(origin["generator_candidates"], use_container_width=True, hide_index=True)
                    if origin.get("provider_issues"):
                        with st.expander("Providers not counted / errors"):
                            st.json(origin["provider_issues"], expanded=True)
                    with st.expander("Provider details and raw evidence"):
                        for item in origin.get("providers", []):
                            st.markdown(f"**{item.get('provider')} — {item.get('model')}**")
                            st.json(item.get("details", {}), expanded=True)
                            with st.expander(f"{item.get('provider')} raw response"):
                                st.json(item.get("raw_response", {}), expanded=False)
                    with st.expander("What TRACEWEAVE used as evidence"):
                        st.json(origin.get("evidence_basis", {}), expanded=True)
                        st.caption(origin.get("limitations", ""))
                else:
                    css = {"green": "good", "red": "bad", "amber": "unknown"}.get(origin.get("color"), "unknown")
                    st.markdown(f'<div class="result {css}"><div class="result-label">{origin.get("status", "DETECTOR RESULT")}</div><div class="result-copy">{origin.get("explanation", "")}</div></div>', unsafe_allow_html=True)
                    if "score_percent" in origin:
                        st.metric("AI-generation estimate", f'{origin["score_percent"]}%')
                    if origin.get("details"): st.caption(str(origin["details"]))
                    if origin.get("frame_scores_percent"):
                        st.write("Video frame scores (%)")
                        st.write(origin["frame_scores_percent"])

            # One clear overall status plus separate structural and AI/provenance results.
            if isinstance(origin, dict) and origin.get("analysis_type") == "multi-engine AI-generated image detection":
                agg = origin.get("aggregate", {})
                score_val = agg.get("mean_ai_likelihood_percent")
                consensus_text = str(agg.get("consensus", ""))
                if not isinstance(score_val, (int, float)):
                    overall_status, overall_color, overall_icon = "AI ORIGIN UNVERIFIED", "amber", "?"
                    overall_explanation = "No configured image detector returned a usable score. Review provider setup and errors."
                elif score_val >= 80 and "LIKELY AI-GENERATED" in consensus_text:
                    overall_status, overall_color, overall_icon = "LIKELY AI-GENERATED SIGNAL", "red", "!"
                    overall_explanation = "Configured detectors collectively indicate AI generation. This remains a probabilistic signal, not proof of source or identity."
                elif score_val <= 20 and "LIKELY NON-AI" in consensus_text:
                    overall_status, overall_color, overall_icon = "LIKELY NON-AI SIGNAL", "green", "✓"
                    overall_explanation = "Configured detectors lean toward non-AI. This does not prove the image is an original camera photo, unedited, or authentic."
                else:
                    overall_status, overall_color, overall_icon = "MIXED / INCONCLUSIVE", "amber", "?"
                    overall_explanation = "Provider outputs are uncertain or disagree. Do not label this image real or fake from this result alone."
            elif ai["matched_indicators"]:
                overall_status = "REVIEW REQUIRED"
                overall_color = "amber"
                overall_icon = "!"
                overall_explanation = (
                    "AI-related or provenance strings were found. Review the indicators below. "
                    "This is not proof that the image is AI-generated; the structural check is shown separately."
                )
            elif report["triage_color"] == "red":
                overall_status = "STRUCTURAL WARNING"
                overall_color = "red"
                overall_icon = "!"
                overall_explanation = report["triage_explanation"]
            elif report["triage_color"] == "amber":
                overall_status = "UNVERIFIED"
                overall_color = "amber"
                overall_icon = "?"
                overall_explanation = report["triage_explanation"]
            else:
                overall_status = "NO KNOWN FLAGS FOUND"
                overall_color = "green"
                overall_icon = "✓"
                overall_explanation = (
                    "No structural issue or known AI marker was found by these checks. "
                    "This does not prove the file is genuine or human-made."
                )

            css_class = {"green": "good", "red": "bad", "amber": "unknown"}[overall_color]
            st.markdown('<div class="eyebrow">03 / Overall assessment</div>', unsafe_allow_html=True)
            st.markdown(
                f'''<div class="result {css_class}"><div style="display:flex;align-items:center;gap:1rem"><div style="font-size:2.4rem;font-weight:700">{overall_icon}</div><div><div class="result-label">{overall_status}</div><div class="result-copy">{overall_explanation}</div></div></div></div>''',
                unsafe_allow_html=True
            )

            structural_cls = {"green": "good", "red": "bad", "amber": "unknown"}[report["triage_color"]]
            st.markdown(
                f'''<div class="panel"><div class="eyebrow">Structural check</div><div class="result {structural_cls}"><div class="result-label">{report["triage_status"]}</div><div class="result-copy">{report["triage_explanation"]}</div></div></div>''',
                unsafe_allow_html=True
            )

            if ai["matched_indicators"]:
                with st.expander("View AI/provenance strings found"):
                    st.json(ai["matched_indicators"], expanded=True)
            m1, m2, m3, m4 = st.columns(4)
            with m1: st.markdown(f'<div class="metric-card"><div class="metric-label">FILE SIZE</div><div class="metric-value">{len(data)/1024:.1f} KiB</div></div>', unsafe_allow_html=True)
            with m2: st.markdown(f'<div class="metric-card"><div class="metric-label">DETECTED TYPE</div><div class="metric-value">{report["detected_signature"]}</div></div>', unsafe_allow_html=True)
            with m3: st.markdown(f'<div class="metric-card"><div class="metric-label">METADATA FIELDS</div><div class="metric-value">{sum(len(v) if isinstance(v, dict) else 1 for v in report["metadata"].values())}</div></div>', unsafe_allow_html=True)
            with m4: st.markdown(f'<div class="metric-card"><div class="metric-label">EXTENSION CHECK</div><div class="metric-value">{"Mismatch" if report["signature_extension_mismatch"] else "No mismatch" if report["detected_signature"] != "Unknown / unsupported signature" else "Unverified"}</div></div>', unsafe_allow_html=True)
            st.write("")
            detail_col, meta_col = st.columns([1, 1], gap="large")
            with detail_col:
                st.markdown('<div class="panel"><div class="panel-title">File intelligence</div>', unsafe_allow_html=True)
                kv("File name", uploaded.name)
                kv("Extension", report["extension"])
                kv("Reported MIME", report["reported_mime_type"])
                kv("Signature", report["detected_signature"])
                kv("Bytes", f'{len(data):,}')
                kv("Analysis time (UTC)", report["analysis_time_utc"])
                st.markdown('</div>', unsafe_allow_html=True)
                st.markdown('<div class="panel"><div class="panel-title">SHA-256 fingerprint</div>', unsafe_allow_html=True)
                st.code(report["sha256"], language=None)
                st.caption("Use this fingerprint to check whether another copy has exactly the same bytes.")
                st.markdown('</div>', unsafe_allow_html=True)
            with meta_col:
                st.markdown('<div class="panel"><div class="panel-title">Metadata & embedded properties</div>', unsafe_allow_html=True)
                if report["metadata"]:
                    st.json(report["metadata"], expanded=True)
                else:
                    st.caption("No metadata fields were extracted.")
                st.markdown('</div>', unsafe_allow_html=True)
            with st.expander("Binary-level evidence profile"):
                st.json(report.get("binary_profile", {}), expanded=True)
                st.caption("Binary entropy, magic bytes and SHA-256 describe file structure/integrity; none is a standalone AI-origin test.")
            if origin:
                report["origin_detection_result"] = origin
            with st.expander("Interpretation, limitations and evidence notes"):
                for note in report["interpretation"]:
                    st.markdown(f"- {note}")
            out = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
            st.download_button("⬇  Download forensic JSON report", out, file_name=f"{Path(uploaded.name).stem}_traceweave_report.json", mime="application/json")

with compare_tab:
    st.markdown('<div class="eyebrow">Binary comparison</div><h2 style="margin-top:.2rem">Compare two file versions</h2><p class="small-muted">Use a trusted original as Version A when possible. A difference proves only that the byte sequences differ—not why or when.</p>', unsafe_allow_html=True)
    left, right = st.columns(2, gap="large")
    with left:
        st.markdown('<div class="panel"><div class="panel-title">Version A · Reference</div>', unsafe_allow_html=True)
        original = st.file_uploader("Upload reference file", key="a")
        st.markdown('</div>', unsafe_allow_html=True)
    with right:
        st.markdown('<div class="panel"><div class="panel-title">Version B · Compare</div>', unsafe_allow_html=True)
        changed = st.file_uploader("Upload comparison file", key="b")
        st.markdown('</div>', unsafe_allow_html=True)
    if original and changed:
        a, b = original.getvalue(), changed.getvalue()
        if len(a) > MAX_BYTES or len(b) > MAX_BYTES:
            st.error("Each file must be 25 MB or smaller.")
        else:
            ha, hb = sha256_bytes(a), sha256_bytes(b)
            same = a == b
            status_cls = "good" if same else "bad"
            status_text = "IDENTICAL BYTES" if same else "BYTE DIFFERENCE FOUND"
            st.markdown(f'<div class="result {status_cls}"><div class="result-label">{status_text}</div><div class="result-copy">{"Both files have the same SHA-256 and are byte-for-byte identical." if same else "The files differ. This alone does not establish tampering, malicious intent, or when changes occurred."}</div></div>', unsafe_allow_html=True)
            c1, c2 = st.columns(2)
            with c1:
                st.markdown('<div class="panel"><div class="panel-title">Version A</div>', unsafe_allow_html=True)
                kv("File", original.name); kv("Size", f"{len(a):,} bytes"); kv("SHA-256", ha)
                st.markdown('</div>', unsafe_allow_html=True)
            with c2:
                st.markdown('<div class="panel"><div class="panel-title">Version B</div>', unsafe_allow_html=True)
                kv("File", changed.name); kv("Size", f"{len(b):,} bytes"); kv("SHA-256", hb)
                st.markdown('</div>', unsafe_allow_html=True)
            first_diff = next((i for i in range(min(len(a), len(b))) if a[i] != b[i]), None)
            if not same:
                if first_diff is not None: st.info(f"First differing byte offset: **{first_diff:,}**")
                elif len(a) != len(b): st.info(f"Shared prefix matches; file lengths differ after byte offset **{min(len(a), len(b)):,}**.")
            compare_report = {"analysis_time_utc": datetime.now(timezone.utc).isoformat(), "version_a": {"filename": original.name, "size_bytes": len(a), "sha256": ha}, "version_b": {"filename": changed.name, "size_bytes": len(b), "sha256": hb}, "byte_for_byte_identical": same, "first_differing_byte_offset": first_diff, "interpretation": "A difference does not by itself establish malicious tampering, authorship, or the time of modification."}
            st.download_button("⬇  Download comparison report", json.dumps(compare_report, indent=2).encode(), file_name="traceweave_comparison.json", mime="application/json")

st.markdown("---")
st.markdown('<div class="small-muted">TRACEWEAVE ADVANCED · Digital evidence matters. Preserve originals, record hashes, and avoid treating automated indicators as definitive conclusions.</div>', unsafe_allow_html=True)
