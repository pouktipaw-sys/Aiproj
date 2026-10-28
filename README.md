# WEB ATTACK SURFACE LAB

*A small security project built to learn by doing, one careful step at a time.*

I wanted a project that would help me understand how to look at a web application's exposed surface without pretending that a beginner's script can replace a real penetration test. So I kept the scope intentionally small: one URL, one ordinary HTTP request, a few response-header observations, and a report I can explain.

The goal is not to produce a scary number of findings. It is to make the process understandable, repeatable, and safe.

## What it does

- Checks the requested URL against an explicit scope before making a request.
- Allows loopback addresses by default; other hosts need an explicit allowlist entry.
- Makes one GET request and does not follow redirects or read the response body.
- Looks for a small set of common security headers and notes when the URL uses HTTP.
- Redacts common secret-like header values and sensitive query parameters in the report.
- Exports JSON and Markdown reports.
- Includes an offline demo, unit tests, and a GitHub Actions workflow.

## Try the offline demo first

You do not need a target website or a running lab to see how the tool works.

Requires Python 3.11 or newer.

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
python -m web_attack_surface_lab --help
python -m web_attack_surface_lab demo --output reports/demo
python -m pytest -q
```

On Windows PowerShell, activate the environment with `.venv\\Scripts\\Activate.ps1` before installing.

The demo is synthetic: it does not contact the internet. Open `reports/demo/report.md` to read the report, or `reports/demo/report.json` to see the structured data.

## Try a local application you control

Start a local web application on your own machine, then run:

```bash
python -m web_attack_surface_lab scan http://127.0.0.1:8000/ --output reports/local
```

For a non-loopback host, the hostname must be explicitly allowed. Only do this when you own the system or have written permission:

```bash
python -m web_attack_surface_lab scan https://lab.example/ --allow-host lab.example --output reports/lab
```

The allowlist is a technical boundary, not proof of authorization. The tool does not follow redirects, crawl pages, submit forms, or exploit anything.

## What the results mean (and do not mean)

A missing header is an observation worth reviewing, not automatically a vulnerability. Whether a header is appropriate depends on the application and how it is deployed. The report is a starting point for manual verification, not a verdict that a system is secure or insecure.

## Project map

- `src/web_attack_surface_lab/`: CLI, scope checks, passive observations, and report writers.
- `tests/`: tests for scope validation, redaction, reporting, and the offline demo.
- `docs/PROJECT_JOURNEY.md`: why I made these design choices and what I want to learn next.
- `docs/DEMO_GUIDE.md`: a short walkthrough for someone reviewing the project.
- `docker-compose.yml`: optional OWASP Juice Shop lab bound to loopback.

## A note about learning

This is a learning project, not a certified scanner and not a professional penetration test. I am using it to practise writing Python, thinking about scope, handling data carefully, and explaining technical decisions clearly. I will only describe tests I have actually run, and I will not claim to have assessed a live target unless I had authorization and did the work.

## Safety

Only test systems you own or have explicit written permission to assess. If you are unsure whether a test is authorized, use the offline demo instead.

## License

MIT. See [LICENSE](LICENSE).
