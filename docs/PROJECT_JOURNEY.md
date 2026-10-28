# Project journey: learning through small, careful steps

## Why I chose this project

I am building my cybersecurity skills from a software-development foundation. I wanted something practical that I could explain line by line, rather than a large tool I could run without fully understanding. This project is one step in that learning process, not a claim that I already work as a penetration tester.

## The question behind it

What can I learn from a single normal HTTP response, and how can I record those observations without drifting outside the system I intended to test?

That question led to a deliberately limited tool: one URL, one GET request, no crawling, no payloads, no exploitation, and no automatic redirect following.

## Decisions I want to be able to explain

- **Scope comes first.** The tool rejects non-loopback hosts unless a hostname is explicitly allowed.
- **Small is intentional.** A narrow tool is easier to test and understand than a pretend all-in-one scanner.
- **Redirects stay off.** A redirect can lead somewhere different from the original target.
- **Reports should be useful.** JSON supports later processing; Markdown is easier for a person to read.
- **Sensitive values should not be copied into reports.** Common authorization headers, cookies, and secret-like query parameters are redacted.
- **Findings need context.** A missing header is not automatically a vulnerability; the application and its deployment matter.

## What I am learning

This project gives me practice with Python modules, command-line arguments, URL parsing, HTTP response headers, test design, JSON, Markdown, and GitHub Actions. It also forces me to think about safety boundaries and the limits of a simple tool.

## What I would improve next

1. Add tests around more unusual URL forms and network edge cases.
2. Make the report include clearer evidence and confidence without overstating severity.
3. Review the checks against reliable security guidance.
4. Run the tool against a local training target and document what I observe.
5. Keep the README honest about what has and has not been tested.

## Integrity note

The offline demo does not contact a real service. CI results describe the code at a particular commit; I should check the latest workflow before saying that the current version passes. I will not invent scan results or claim that DMC DEFENSE, or any other real organization, has been tested.
