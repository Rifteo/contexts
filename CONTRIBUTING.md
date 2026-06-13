# Contributing to Rifteo Contexts

Thanks for contributing to the Rifteo open security toolkit.

## Adding a new context

1. Fork this repo
2. Create a folder named after your context (lowercase kebab-case)
3. Add a `CONTEXT.md` following the [Context Structure Guide](CONTEXT_GUIDE.md)
4. Open a pull request against `main`

CI will validate your `CONTEXT.md` before merge — make sure `name` matches the folder name, `l0` is present and under 120 characters, and L1/L2 sections exist.

## Improving an existing context

Open a PR with your changes. Include a short description of what you updated and why.

## Guidelines

- One context per PR
- Follow the format in [CONTEXT_GUIDE.md](CONTEXT_GUIDE.md)
- Keep `l0` as a single inline string — no multiline YAML
- L2 must include a reporting phase
- No offensive tooling that requires authorization to use — contexts are methodology guides, not attack scripts

## Questions

Open an issue or start a discussion.
