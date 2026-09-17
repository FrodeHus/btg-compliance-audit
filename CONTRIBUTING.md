# Contributing

Thank you for your interest in improving Break-the-glass compliance monitor.

## How to contribute

1. Fork the repository.
2. Create a feature branch from `main`.
3. Make the smallest change that addresses the issue or adds the improvement.
4. Update documentation when behavior or deployment steps change.
5. Submit a pull request with a clear summary and testing notes.

## Development workflow

- Review the setup steps in [README.md](README.md) and [INSTALL.md](INSTALL.md).
- For local validation, use the PowerShell workflow in [LOCAL_TEST.md](LOCAL_TEST.md).
- Keep changes scoped and avoid broad refactors without a clear reason.

## Required validation

Before opening a pull request, please validate the relevant work:

```powershell
pwsh
./runbook/Test-BreakGlassCompliance.ps1 -BreakGlassGroupIds '<group-object-id>' -UseGraphPowerShell -SkipLogAnalytics
```

For Terraform changes:

```bash
cd terraform
terraform fmt
terraform validate
```

If your change affects deployment behavior, include a short note describing what you tested and what changed.

## Pull request expectations

- Include a clear description of the problem and the fix.
- Link the related issue if one exists.
- Keep the PR focused on a single topic.
- Confirm docs were updated if the user-facing workflow changed.

## Security issues

Please do not open public issues for security vulnerabilities. Follow the process in [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the Microsoft Open Source Code of Conduct. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
