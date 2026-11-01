# SYCUR — Six-Scanner Test Fixtures

This folder contains intentionally insecure, **static-analysis-only** fixtures for testing the six SYCUR scanners:

| Scanner | Fixture / expected signal |
|---|---|
| Gitleaks | `credentials.env` — synthetic GitHub-token-shaped string |
| Semgrep | `vulnerable_app.py` — unsafe `eval` and shell execution |
| Bandit | `vulnerable_app.py` — B307, B602 and hardcoded-password patterns |
| Trivy | Whole folder — secret, vulnerable dependency and Terraform misconfiguration checks |
| OSV-Scanner | `requirements.txt` — deliberately outdated package pins |
| Checkov | `main.tf` — public S3 ACL and SSH open to the internet |

## Safety

- These are deliberately vulnerable examples for an isolated test repository.
- The credential-shaped value is synthetic and is **not a real credential**.
- Do not run `vulnerable_app.py`.
- Do not run `terraform apply` or deploy `main.tf`.
- Do not use these fixtures in production.
- Scan the folder as source; no vulnerable function is called by default.

## Suggested scanner commands

Run from this directory, using the versions/configuration installed in your environment:

```bash
gitleaks detect --source . --no-git
semgrep scan --config p/python --config p/security-audit .
bandit -r vulnerable_app.py
trivy fs --scanners vuln,misconfig,secret .
osv-scanner scan source -r requirements.txt
checkov -d . --framework terraform
```

Scanner rule IDs and exact findings depend on the installed scanner versions and rule packs. A scanner may report additional findings or use different wording.
