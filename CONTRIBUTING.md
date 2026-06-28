# Contributing to AI Cyber Security Suite

Thank you for considering contributing! This document outlines the process for contributing code, documentation, and bug reports.

---

## Development Setup

1. **Fork and clone** the repository.
2. Follow the [Deployment Guide](docs/DEPLOYMENT.md) to set up local development.
3. Create a feature branch: `git checkout -b feature/my-awesome-feature`

---

## Code Style

### Python (Backend & ML)
- Formatter: `black`
- Linter: `ruff` or `flake8`
- Type hints are required on all public functions.

### TypeScript (Frontend & Extension)
- Formatter: `Prettier` (via ESLint config)
- All components must be typed — avoid `any`.

---

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add DNS lookup to threat intel
fix: prevent race condition in service worker
docs: update API reference
refactor: extract scan logic into service
test: add unit tests for feature extractor
```

---

## Pull Request Guidelines

- Keep PRs focused and small.
- Include a clear description of the change and **why** it was made.
- All new features should include unit tests.
- Pass all CI checks before requesting review.

---

## Reporting Bugs

Open a GitHub Issue with:
- OS and software versions
- Steps to reproduce
- Expected vs. actual behaviour
- Any relevant logs or screenshots

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
