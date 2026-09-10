# Changelog

## 1.1.0 - 2026-09-10

- v2 API: single options pointer constructors, generic `Add` dispatcher, and `runs_in` alias
- Threat `status` (`Open`/`Mitigated`) and `severity` scoring (`Low`/`Medium`/`High`/`Critical`)
- Validation at addition time for boundaries and data flows
- Case-insensitive sensitive data type matching and scoped Elevation of Privilege rules
- `Version` constant

## 1.0.0 - 2026-09-01

- Initial Go release
- Declarative `Model`, `Component`, `Boundary`, and `DataFlow` types
- STRIDE threat analyzer with mitigation catalog
- pkg.go.dev ready with godoc and examples
