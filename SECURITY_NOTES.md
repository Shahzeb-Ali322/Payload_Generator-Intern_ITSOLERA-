# Security notes and design review

## Intended use

Offline generation of boundary-test strings for an owned or explicitly authorized application. The program does not contact a target or determine whether it is vulnerable.

## Threat model

Treat generated values as potentially significant when a downstream system mishandles input. A delimiter can still affect a vulnerable query or shell context even though the generator appends no command or query logic. Run probes only in a disposable lab/staging environment with test data and monitoring.

## Built-in controls

- Fixed, reviewable probe catalog; no arbitrary payload parameter.
- Correlation token restricted to ASCII letters, digits, `_`, and `-`.
- Encoders operate only on catalog values.
- No HTTP client, DNS lookup, socket, subprocess, browser execution, clipboard, or target configuration.
- JSON/text output only; refuses to overwrite existing output files.
- No active JavaScript, SQL operators/comments/unions/time delays, or shell commands.

## Validation performed

- Unit tests cover the fixed categories, token validation, encoding, JSON/text output, file export, and overwrite protection.
- Sample corpus parsed as JSON and checked for 9 entries covering all 3 categories.
- Demo transcript checked for each category.

## Application-side recommendations

- **HTML/XSS:** encode for the exact output context; prefer safe DOM APIs that treat untrusted values as text. Do not rely on a blacklist or WAF as the control.
- **SQL:** use parameterized queries and least-privilege database accounts; avoid returning database exceptions to users.
- **OS command handling:** avoid shell command construction. Use a fixed executable with an argument array, strict allowlists, and least privilege; isolate any process that must run.

## Limitations

This is not an exploit-validation framework, scanner, WAF compatibility suite, or substitute for a manual assessment. It intentionally omits active proof-of-execution and evasion cases, plus Burp/ZAP submission, so it cannot establish bypass resistance or confirm exploitable impact.
