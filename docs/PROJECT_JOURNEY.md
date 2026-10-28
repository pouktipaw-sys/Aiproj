# Project journey

## Problem
A beginner learning web security benefits from repeatable, scoped and documented observations. This project implements a small, understandable slice rather than claiming to be a full scanner.

## Design decisions
1. Validate scope before any network request.
2. Make one GET request only; no crawling, forms, payloads or exploitation.
3. Do not follow redirects because they may leave the declared scope.
4. Provide an offline synthetic demo.
5. Export both JSON and Markdown.
6. Treat missing headers as observations, not proof of a vulnerability.

## Next learning steps
- Add tests for malformed URLs and IPv6 loopback.
- Review browser-specific header guidance and false positives.
- Add structured evidence and confidence levels.
- Review DNS rebinding and network-level scope risks before expanding the tool.

## Integrity note
Only describe tests you have actually run. Check the GitHub Actions result before claiming CI verification.
