# @at-series/command-policy

## 0.1.1

### Patch Changes

- 14f4de4: Initial public command-policy analyzers for shell, Python, SQLite, MySQL, and Redis.
- 0f555e1: Tighten command-policy matching: classify path-sensitive readers (`cut`/`jq`/`wc` and peers), expand sensitive path and SQL schema checks, parse awk/sed write/exec forms, split per-domain rule versions, attach shell evidence to command IR ranges, and reduce false reviews for common read-only wrappers and Redis reads.
- a978e07: Optimize package size and evaluation latency: esbuild minification, shared tree-sitter runtime chunk, resolver-level language caching, warmup API, fast limits validation, synchronous embedded gate, lazy whole-source location, and MySQL executable comment security fix.
