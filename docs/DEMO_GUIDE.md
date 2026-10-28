# A short, honest project walkthrough

This walkthrough takes about three to five minutes and uses only the synthetic demo.

## 1. Start with the idea

“I wanted to practise a small part of web security in a way I could understand and explain. This tool checks a single HTTP response for a few common security-header observations. It is deliberately not a full scanner.”

## 2. Show the safety boundary

Open `src/web_attack_surface_lab/scope.py` and explain that loopback is allowed by default. A non-loopback hostname needs an explicit allowlist entry, and permission to test still has to come from the system owner.

## 3. Run the offline demo

```bash
python -m web_attack_surface_lab demo --output reports/demo
```

This command uses synthetic data. It does not contact `demo.invalid` or any other host.

## 4. Read the report

Open `reports/demo/report.md`. Pick one observation and explain the recommendation. Then show `report.json` and explain how structured output could be consumed by another tool.

## 5. Be clear about the limits

“This project only observes a few response headers. A missing header is not automatically a vulnerability, and the report needs human review. I have not used it to test DMC DEFENSE or any other company.”

A good demonstration is one where you can explain the trade-offs, not one where you claim the tool can do everything.
