# Architecture Decision Records

This document captures the major design decisions behind the `threat-modeling` library and how they are expected to guide future work.

---

## ADR-001: Multi-Language Support

### Context

The library targets engineering teams that write threat models in the same language as their production code. Different organizations (and even different teams in the same organization) use different primary languages, so a threat-modeling library that is available in Go, Python, Rust, and TypeScript lowers adoption friction.

### Decision

Ship the same conceptual model and STRIDE analyzer in four language ports: **Go**, **Python**, **Rust**, and **TypeScript**.

### Consequences

- **Pros**: Teams can threat-model in their native language; the same design reviews can be reused across polyglot codebases.
- **Pros**: Each port can follow idiomatic patterns (constructors, builders, exceptions, `Result`, etc.).
- **Cons**: Features must be implemented and tested in four places.
- **Mitigation**: `API.md` is the single source of truth for shared behavior. CI runs the same scenarios in all four languages. The version numbers are kept in lock-step.

---

## ADR-002: Keeping the Ports in Sync

### Context

With four language implementations, the risk of API drift is high. A change in one port that is not reflected in the others breaks the promise of cross-language parity.

### Decision

Use a shared v2 public API specification plus cross-language CI to keep the ports synchronized.

### Rules

1. Every new feature, field, or behavior change must be added to `API.md` before (or alongside) code changes.
2. If a feature cannot be idiomatically implemented in a given language, the language port may omit the surface but must document the limitation in `API.md`.
3. All four language test suites must be updated for any analyzer or model behavior change.
4. All four packages share the same `MAJOR.MINOR.PATCH` version number and are released together.
5. CI blocks merges that break any port (`go`, `python`, `rust`, `typescript`).

---

## ADR-003: Adding a New STRIDE Category

### Context

STRIDE is the current classification scheme, but the library may need to support additional threat categories in the future (e.g., privacy-specific categories, supply-chain, or custom rules).

### Decision

A new STRIDE or STRIDE-like category can only be added when it has a clear, testable mapping to components and/or data flows.

### Process

1. Update `ThreatKind` in all four languages.
2. Add a human-readable `description` and at least one `mitigation` for the new category.
3. Add `component_threats` and/or `flow_threats` logic that decides when the new category is generated.
4. Define the control that sets the resulting `Threat` to `Mitigated` (if any). If no control is modeled, the threat is always `Open`.
5. Add status rules in `API.md`.
6. Add regression tests in all four language test suites.
7. Bump the minor version because this is a behavioral change.

### Notes

- New categories should not overlap in purpose with an existing one unless the analyzer can distinguish them based on model fields.
- If a category only applies to one environment (e.g., browser-specific), it should still be represented in the shared `ThreatKind` enum and documented as optional.
