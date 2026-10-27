# Contributor Guidelines (Quality & Security)

- **Branching:** Work on a feature branch, open a pull request to `main`. Direct pushes to `main` are blocked by branch protection.
- **Required checks:** `ruff check .`, `lint-test`, `security` (Gitleaks), `docker` (build + `docker compose up -d --wait` + smoke test), `ips` (3.10/3.12), `ips-cyber`, `dashboard`, and `Analyze (python)` (CodeQL) must all pass.
- **Reviews:** At least **1 approving review** is required. Reviews are dismissed when new commits are pushed.
- **Conversation resolution:** All PR review threads must be resolved before merging.
- **Linting/formatting:** `ruff check .` must be clean. Run `ruff format` if you add/modify Python files.
- **Tests:** Add or update tests when changing behaviour. All local test suites must pass with 0 failures/skips.
- **Secrets:** Never commit `.env`, keys/certificates, private face photos, or large model weights. `make setup` generates them. Pre-commit / CI Gitleaks will flag leaks.
- **Security:** Avoid `eval`, `shell=True` with untrusted input, and unsafe deserialization. Use `yaml.safe_load` where possible (the IoT-IPS loaders use a safe custom loader). Run `bandit -r ...` for new code paths if in doubt.
- **Dependencies:** Dependabot is enabled for GitHub Actions, Docker and pip. Use `pip-audit` locally for new requirements.
- **Docker:** `docker compose config -q` must pass. Keep healthchecks and least-privilege ACLs intact.
- **Commits:** Use clear, descriptive messages. Avoid force-pushes to `main`.
