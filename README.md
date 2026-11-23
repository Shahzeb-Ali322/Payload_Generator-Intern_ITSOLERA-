# ITSOLERA Safe Input Test Generator

A small, dependency-free Python CLI for producing **fixed, inert input-boundary probes** for authorized web-application labs. It is an offline test-data generator—not a scanner, exploit framework, or WAF-bypass tool.

## Safety scope

The assignment requests exploit-ready XSS, SQL injection, and command-injection strings with WAF/filter bypasses. This implementation deliberately does **not** generate executable JavaScript, SQL logic, shell commands, blacklist bypasses, or real-world WAF evasions. Its URL/Base64/hex/Unicode options only transform the built-in canary probes; the CLI does not accept arbitrary payload text. Nothing is sent over a network, copied to a target, or executed.

Command-boundary probes contain trailing metacharacters but no following command. They are still input test strings: only use them with an application and environment you own or are explicitly authorized to test. Do not paste them into a production system or a shell.

## Features

- XSS output-encoding probes: a non-script custom element and special characters.
- SQL input-boundary probes: quote, parenthesis, and backslash delimiters; no query logic.
- Command-input boundary probes: trailing `;`, `&&`, and `|`; no command is appended.
- Optional URL, Base64, hex, or Unicode representation of the fixed probes.
- Human-readable or JSON output, with an optional file export.
- Random correlation token per run; existing output files are not overwritten.
- Python standard library only; no target, credentials, or network access required.

## Requirements

- Python 3.10 or newer
- No third-party packages

## Usage

From this directory:

```bash
# Generate all fixed probes as text
python safe_input_tests.py

# Generate XSS-category probes using URL representation
python safe_input_tests.py --xss --encode url

# Export SQL boundary probes as JSON (output file must not already exist)
python safe_input_tests.py --sqli --encode base64 --format json --output results/sqli.json

# Generate command-boundary probes
python safe_input_tests.py --command

# Run the tests
python -m unittest discover -s tests -v
```

Selectors: `--xss`, `--sqli`, `--command` (alias `--cmd`), or `--all` (the default). Choose `--encode` from `none`, `url`, `base64`, `hex`, and `unicode`. Choose `--format text|json`. `--output PATH` writes a file and refuses to overwrite an existing path.

## Probe record format

Each JSON entry contains:

- `category` and `id`: probe family and stable case identifier.
- `token`: per-run correlation marker.
- `input`: the probe in the selected representation.
- `encoding`: the selected representation.
- `purpose`: a short explanation of what boundary to inspect.
- `requires_authorized_lab`: always `true`.

## Recommended validation workflow

1. Use a disposable local/staging app with test data and written authorization.
2. Submit a probe through the app's ordinary input path; the generator itself does not submit it.
3. Inspect context-specific output encoding, validation behavior, and server-side errors without trying to execute code or alter data.
4. Prefer parameterized SQL APIs and argument-array process APIs; do not rely on WAF rules as the primary control.
5. Stop if a test causes unexpected state changes or affects users. Document the request, observed response, remediation, and retest.

This project produces test inputs only; it does not establish whether an application is vulnerable. A clean result is not proof of security.

## Files

- `.gitignore` — excludes Python caches, local environments, and `.env` files.
- `README.md` — setup, usage, scope, and workflow.
- `SECURITY_NOTES.md` — threat model, controls, and limitations.
- `safe_input_tests.py` — CLI and fixed probe catalog.
- `tests/test_safe_input_tests.py` — standard-library unit tests.
- `sample_payloads.json` — generated sample corpus.
- `demo_output.txt` — captured CLI text output.

The project does not include a GUI, Burp/ZAP integration, clipboard access, or a remote GitHub repository. Those are intentionally left out; integrations that submit probes would require a separately scoped and explicitly authorized target.
