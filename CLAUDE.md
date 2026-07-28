# Bulwrk

A modern, open-source system cleaner and family device-security platform for
Windows, macOS, and Linux built with Electron. (Desktop cleaning engine forked
from Kudu; product name is Bulwrk. Public domain/email stay open.)

## Releasing

All releases are done via a single command:

```
npm run release -- patch|minor|major
```

This handles everything: version bump, changelog generation, commit, tag, push, and triggers CI to build and publish.

## Testing

```
npm test # run all tests once (vitest run)
npm run test:watch # run tests in watch mode
npm run validate:rules # validate rule JSON files against schema
```

## Development

```
npm run dev
```

## Commit Conventions

Always use [Conventional Commits](https://www.conventionalcommits.org/). Format:

```
<type>(<scope>): <short summary>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`.

Examples:
- `feat(rules): add new browser cache cleaning rule`
- `fix(scanner): handle missing registry keys on Windows`
- `refactor(ui): extract settings panel into separate component`
- `test(engine): add unit tests for file size calculation`

Breaking changes must include `!` after the type/scope (e.g., `feat(api)!: redesign plugin interface`).
