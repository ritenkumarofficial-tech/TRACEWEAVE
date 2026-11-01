# TRACEWEAVE Advanced — Free-first image forensics

## Free local AI-image model (no API key)

The app can run `capcheck/ai-image-detection` locally through Hugging Face Transformers. It downloads model weights the first time and then caches them on this computer. It does not upload the image to a detector provider. The checkpoint is trained mainly on CIFAKE / older generators, so results can be wrong for newer models, edited images, screenshots and compressed images.

Recommended on Apple Silicon: Python 3.11 or 3.12. First install the normal requirements, then the optional model dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip install -r requirements-local-model.txt
python3 -m streamlit run app.py
```

Open `http://localhost:8501`, upload an image, keep **Include free local Hugging Face model** checked, and select **Run multi-engine image scan**. The first run needs internet to download the model; later runs use the cached model.

## Sightengine API (image detection)

Sightengine's `genai` image endpoint can be used alongside the optional local model. Its free plan has usage limits; the current provider documentation says some features (including AI video, AI speech and AI music detection) are paid-plan-only. Check your account's current access before using those routes.

To save credentials locally without displaying the secret, run:

```bash
chmod +x setup_sightengine.sh
./setup_sightengine.sh
```

The script asks for your API User and API Secret, writes them to `.env`, and restricts file permissions. If a secret was exposed in a chat or screenshot, rotate it first. Never put API secrets in source code or share them publicly.

AI or Not, WasItAIGenerated and Hive adapters are optional and are not required for the free-first setup. Their free tiers/credits are not assumed to be unlimited. Leave their keys unset unless you intentionally configure them.

## Evidence shown

- Model outputs and agreement/disagreement
- SHA-256, file signature, MIME/extension agreement, entropy and image metadata
- EXIF/embedded provenance where present

Metadata, entropy and file signatures describe the file; they do not independently prove human or AI authorship. The ensemble mean is not a calibrated real-world probability. AI detection can false-positive real photos and false-negative AI images. Do not use this result alone for consequential judgments.
