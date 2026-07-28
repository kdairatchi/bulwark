# Contributing to Bulwrk

Thanks for your interest in contributing! Bulwrk is a community-driven project and we welcome all contributions — bug reports, feature requests, documentation improvements, and code.

## Getting Started

1. Fork the repository
2. Clone your fork and create a branch:
   ```bash
   git clone https://github.com/YOUR_USERNAME/kudu.git
   cd kudu
   git checkout -b my-feature
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Start the dev server:
   ```bash
   npm run dev
   ```

## Project Structure

```
rules/           # Cleaner rule definitions (JSON) — edit these to add new cleaners!
src/
├── main/        # Electron main process
├── preload/     # Preload scripts (bridge between main & renderer)
├── renderer/    # React frontend
└── shared/      # Shared types and utilities
```

## Adding Cleaner Rules

Want to add support for cleaning a new app's cache? You don't need to write any TypeScript — just edit a JSON file in the [`rules/`](rules/) directory. See the **[Rules Contributing Guide](rules/RULES.md)** for full instructions and the **[Rules Catalog](rules/CATALOG.md)** for what's already covered.

**Fastest way** — use the interactive generator:
```bash
npm run new-rule
```

**Manual way:**
1. Add your app to `rules/<platform>/apps.json`
2. Run `npm run validate:rules` to check your changes
3. Run `npm test` to make sure everything passes
4. Submit a PR!

**Helpful tools for contributors:**
```bash
npm run find-cache       # Discover uncovered cache dirs on your machine
npm run preview-rule     # Dry-run a rule to see what it would clean
npm run parity-check     # Find cross-platform coverage gaps
npm run catalog          # Regenerate the rules catalog
```

## Making Changes

- Keep changes focused — one feature or fix per PR.
- Follow the existing code style.
- Write or update tests if applicable (`npm test`).
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages:
  - `feat: add new feature`
  - `fix: resolve bug`
  - `docs: update readme`
  - `chore: update dependencies`

## Submitting a Pull Request

1. Make sure tests pass: `npm test`
2. Make sure the app builds: `npm run build`
3. Push your branch and open a PR against `main`.
4. Fill out the PR template — describe what changed and why.

## Reporting Bugs

Use the [bug report template](https://github.com/kdairatchi/bulwark/issues/new?template=bug_report.md). Include your OS, Bulwrk version, and steps to reproduce.

## Suggesting Features

Use the [feature request template](https://github.com/kdairatchi/bulwark/issues/new?template=feature_request.md).

## Code of Conduct

Be respectful and constructive. We're all here to build something useful.
