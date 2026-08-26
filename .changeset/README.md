# Changesets

This repository publishes one public package, `@at-series/command-policy`.

Add a changeset before merging user-visible analyzer or API changes:

```sh
npx changeset
```

CI publishes from `main` with npm provenance when a release changeset is present.
The workflow is scaffolded; actual publish requires npm and GitHub OIDC credentials.
