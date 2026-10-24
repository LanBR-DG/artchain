# Contributing to ArtChain

Issues and small, focused pull requests are welcome. Chinese and English are both welcome.

## Reproduce first

Use a fresh checkout and disposable data. State your OS, Python version, command,
expected result, actual result, and a minimal example. Remove passwords, mnemonic
phrases, private keys, API keys, original private artworks, and personal data.

```sh
python -m artchain --data ./data selftest
python scripts/smoke_http.py
```

## Changes

Keep the standard-library core usable without optional packages. Add regression
coverage for behavioral fixes. Explain any changes to transaction serialization,
consensus validation, certificates, wallet formats, or storage compatibility.
Update the relevant documentation when command-line or API behavior changes.

Before opening a PR, inspect `git diff --check` and `git diff --cached`.
`.gitignore` does not protect secrets embedded in source or arbitrary backup names.

## Useful first contributions

- HTTP authentication and request-boundary regression tests.
- Reproducible installation checks on additional supported Python versions.
- English UI/documentation improvements with matching Chinese descriptions.
- Measured persistence and replay benchmarks using generated data.

Security-sensitive reports should follow [SECURITY.md](SECURITY.md).
Contributions are distributed under the project's [MIT License](LICENSE).
