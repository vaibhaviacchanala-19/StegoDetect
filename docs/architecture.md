# StegoDetect Architecture

## Overview

StegoDetect is a Flask-based digital-forensics application for reviewing suspicious files, extracting metadata, checking for embedded content, and scoring file risk for incident-response workflows.

## High-level flow

```text
User Upload
   ↓
File validation and hashing
   ↓
Metadata extraction
   ↓
Signature/MIME checks
   ↓
Steganography tool analysis
   ↓
String/Base64/Entropy/Hex review
   ↓
Risk scoring and SOC summary
   ↓
Investigation history + PDF/JSON/HTML exports
```

## Components

### Frontend
- Flask routes in `app.py`
- Jinja templates in `templates/`
- Bootstrap-based dashboard and reporting views

### Core analysis engine
- `modules/file_analyzer.py`: validation, hashing, duplicate detection, safe file naming
- `modules/metadata_analyzer.py`: ExifTool-driven metadata review
- `modules/strings_analyzer.py`: suspicious string detection
- `modules/base64_analyzer.py`: base64 candidate and decode review
- `modules/entropy_analyzer.py`: entropy and anomaly scoring
- `modules/hex_viewer.py`: byte-level preview
- `modules/signature_analyzer.py`: structure and mismatch checks

### Tool integrations
- `modules/tool_manager.py`: wrapper for externally installed forensic tools
- `modules/steghide_analyzer.py`
- `modules/zsteg_analyzer.py`
- `modules/binwalk_analyzer.py`
- `modules/png_analyzer.py`

### Risk and workflow
- `modules/risk_engine.py`: evidence weighting and severity classification
- `database/db.py`: SQLite persistence for investigations and filters
- `modules/report_generator.py`: forensic report creation

## Storage model

The application stores investigation metadata in SQLite and treats uploads and generated reports as temporary working artifacts. Sensitive evidence is never committed to the repository by default.

## Security boundaries

- Uploaded files are never executed.
- File names are sanitized before saving.
- Duplicate detection is based on SHA-256 values.
- External tools are invoked only with argument arrays and timeouts.
- Generated reports are saved under controlled directories.

## Operational notes

- Safe sample files should be used for validation.
- Missing tool detection is reported clearly to the analyst.
- Inconclusive results are labeled as such to avoid false certainty.
