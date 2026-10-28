# WEB ATTACK SURFACE LAB

A safety-first Python CLI for documenting a small slice of a web application's visible attack surface. Designed as a junior application-security learning project.

## Safety by design

- Loopback hosts only by default.
- One explicitly supplied URL and one GET request per run.
- Explicit hostname allowlist required for any non-loopback target.
- Redirects are not followed; no crawling, exploitation, brute force or form submission.
- Bounded request timeout and sanitized response-header values.
- Offline synthetic demo for portfolio walkthroughs.

Only assess systems you own or have explicit written permission to test. An allowlist is a technical boundary, not proof of authorization.

## Quick start

Requires Python 3.11 or newer.

    python -m venv .venv
    python -m pip install -e ".[dev]"
    python -m web_attack_surface_lab --help
    python -m web_attack_surface_lab demo --output reports/demo
    python -m pytest -q

On Windows PowerShell, activate the virtual environment with .venv\Scripts\Activate.ps1 before installing.

## Local-only scan

Run a local application you control, then:

    python -m web_attack_surface_lab scan http://127.0.0.1:8000/ --output reports/local

For a non-loopback hostname, add an explicit allowlist entry only when authorized:

    python -m web_attack_surface_lab scan https://demo.example/ --allow-host demo.example --output reports/demo-target

The tool writes report.json and report.md. It does not follow redirects.

## Repository structure

- src/web_attack_surface_lab/: CLI, scope validation, passive checks and report writers.
- tests/: offline unit tests.
- docs/PROJECT_JOURNEY.md: design decisions and learning plan.
- docs/DEMO_GUIDE.md: short recruiter walkthrough.
- fixtures/: guidance for synthetic data.
- docker-compose.yml: optional local Juice Shop target bound to loopback only.

## Limitations

This is not a full vulnerability scanner or a professional penetration test. Missing headers are observations, not proof of a vulnerability. Manually validate results and document limitations. Use the synthetic demo when you do not have written authorization to test a target.

## Honest portfolio note

Only claim tests you have personally run or that the CI workflow has actually passed. Do not claim a live target was tested unless you tested it with authorization.

## License

MIT. See LICENSE.
