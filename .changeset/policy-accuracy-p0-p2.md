---
"@at-series/command-policy": patch
---

Tighten command-policy matching: classify path-sensitive readers (`cut`/`jq`/`wc` and peers), expand sensitive path and SQL schema checks, parse awk/sed write/exec forms, split per-domain rule versions, attach shell evidence to command IR ranges, and reduce false reviews for common read-only wrappers and Redis reads.
