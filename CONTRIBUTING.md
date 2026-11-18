# Contributing to StegoDetect

Thank you for contributing to StegoDetect. This project is intended for lawful forensic triage and incident-response support in authorized environments.

## Development workflow

1. Fork or clone the repository.
2. Create a virtual environment: `python -m venv .venv`
3. Activate the environment and install dependencies: `python -m pip install -r requirements.txt`
4. Run the verification suite before opening a PR: `python -m pytest -q`
5. Keep uploads, reports, and investigation data out of source control.

## Security expectations

- Never execute uploaded files.
- Never add stored suspicious samples, extracted payloads, or credentials to the repository.
- Validate new checks with real sample files from safe test sets.
- Preserve evidence integrity and avoid fabricating detections.

## Pull request checklist

- New functionality must include focused tests.
- Tool availability must fail gracefully when external utilities are missing.
- Outputs must be evidence-based and clearly labeled as inconclusive when needed.
- Documentation must be updated for new user-facing workflows.

## Code style

- Python 3 with clear, readable function names.
- Prefer small, pure functions for forensic checks.
- Use secure file naming and path validation for all file operations.
