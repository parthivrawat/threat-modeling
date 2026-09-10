# Threat Modeling as Code — v2 Public API Specification

## Goals

- Keep a single, idiomatic API shape across the Go, Python, TypeScript, and Rust implementations.
- Expose enough information in `Threat` results so consumers can filter, sort, and report on actionable items.
- Allow users to record the controls that are already in place so the analyzer can distinguish `open` risks from `mitigated` ones.

## Core Types

All four implementations expose these public types:

- `Component` — an architectural component (API, service, database, browser, ...)
- `Boundary` — a trust boundary that may contain or trust components
- `DataFlow` — a directed interaction between two components
- `Model` — the top-level container that validates and analyzes the model
- `Threat` — a STRIDE finding with a target, description, mitigations, `status`, and `severity`
- `ThreatKind` — the six STRIDE categories
- `ThreatStatus` — `Open` or `Mitigated`
- `Severity` — `Low`, `Medium`, `High`, or `Critical`

### Component

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | yes | — | Stable identifier. |
| `name` | no | `id` | Human-readable name. |
| `type` | no | `service` | `api`, `service`, `database`, `gateway`, `load-balancer`, `browser`, ... |
| `environment` | no | `""` | `k8s`, `container`, `vm`, `browser`, ... |
| `stores` | no | `[]` | Data types the component stores. |
| `handles` | no | `[]` | Data types the component processes. |
| `exposed` | no | `false` | Whether the component is reachable from untrusted actors. |

### Boundary

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | yes | — | Stable identifier. |
| `name` | no | `id` | Human-readable name. |
| `untrusted` | no | `false` | Whether this boundary is an external, hostile zone. |
| `contains` | no | `[]` | Component IDs inside the boundary. |
| `trusts` | no | `[]` | Component IDs explicitly trusted across the boundary. |

### DataFlow

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | yes | — | Stable identifier. |
| `source` | yes | — | Source component ID. |
| `target` | yes | — | Target component ID. |
| `protocol` | no | `""` | e.g. `https`, `tls`, `mtls`, `ssh`. |
| `auth` | no | `""` | e.g. `bearer`, `mtls`, `basic`. |
| `data_types` | no | `[]` | Data types carried by the flow. |

### ThreatStatus

- `Open` — the threat is considered active unless a specific control is in place.
- `Mitigated` — the user has supplied a control that directly addresses this STRIDE category.

### Threat

| Field | Type | Description |
|-------|------|-------------|
| `kind` | `ThreatKind` | STRIDE category. |
| `target` | `string` | Component or flow ID. |
| `description` | `string` | Human-readable explanation. |
| `mitigations` | `string[]` | Recommended actions. |
| `status` | `ThreatStatus` | `Open` or `Mitigated`. |
| `severity` | `Severity` | `Low`, `Medium`, `High`, or `Critical`. |

## Threat Status Rules

A `Threat` is `Mitigated` when the model includes a control that directly counters that STRIDE category.

For **DataFlow** threats:

| Threat | Control that sets `Mitigated` |
|--------|------------------------------|
| Spoofing | `auth` is non-empty. |
| Tampering | `protocol` is one of `https`, `tls`, `mtls`, `ssh`. |
| Information Disclosure | `protocol` is secure AND the flow does not carry sensitive data. |
| Elevation of Privilege | `auth` is non-empty. |
| Repudiation | — (no control modeled; always `Open`). |
| Denial of Service | — (no control modeled; always `Open`). |

For **Component** threats, all statuses are `Open` in v2. Future versions may add a `controls` field to `Component` to enable the same `Mitigated` behavior.

## Severity

`Severity` is a simple risk score assigned to every `Threat`:

- `Low`
- `Medium`
- `High`
- `Critical`

### Component Threat Severity

For component threats, the score is computed from three factors:

- `exposed` — the component is reachable from untrusted actors.
- `sensitive` — the component stores or handles a sensitive data type (case-insensitive).
- `privileged` — the component runs in `k8s`/`container`/`vm` or is an `api`/`gateway`/`load-balancer`.

`score = exposed + sensitive + privileged` (each factor is 0 or 1):

| Score | Severity |
|-------|----------|
| 0 | `Low` |
| 1 | `Medium` |
| 2 | `High` |
| 3 | `Critical` |

### Data Flow Threat Severity

For data-flow threats, the score is computed from:

- `crossing` — the flow crosses a trust boundary.
- `sensitive` — the flow carries a sensitive data type (case-insensitive).
- `insecure` — the flow's protocol is not in the secure set (`https`, `tls`, `mtls`, `ssh`).

`score = crossing + sensitive + insecure`:

| Score | Severity |
|-------|----------|
| 0 | `Low` |
| 1 | `Medium` |
| 2 | `High` |
| 3 | `Critical` |

## Construction Conventions

Each language should follow its idioms, but the logical fields must be the same.

- **Go**: `NewComponent(id, name, opts *ComponentOpts)` where `name` defaults to `id` if empty. `ComponentOpts` supports both `Environment` and the alias `RunsIn` for the same logical field. A single options pointer is preferred over variadic options.
- **Python**: `Component(id, name=None, ..., exposed=False)` with keyword-only options.
- **Rust**: `Component::new(id).name("...").exposed(true)` builder pattern.
- **TypeScript**: `new Component(id, name?, options?)` with an options object.

## API Translation Table

| Construct | Go | Python | Rust | TypeScript |
|-----------|----|--------|------|------------|
| **Component** | `NewComponent(id, name, opts *ComponentOpts)` | `Component(id, name=None, ...)` | `Component::new(id).name(...)` | `new Component(id, name?, options?)` |
| **Boundary** | `NewBoundary(id, name, opts *BoundaryOpts)` | `Boundary(id, name=None, ...)` | `Boundary::new(id).name(...)` | `new Boundary(id, name?, options?)` |
| **DataFlow** | `NewDataFlow(id, src, tgt, opts *FlowOpts)` | `DataFlow(id, src, tgt, ...)` | `DataFlow::new(id, src, tgt).protocol(...)` | `new DataFlow(id, src, tgt, options?)` |
| **Model creation** | `New(name)` | `Model(name)` | `Model::new(name)` | `new Model(name)` |
| **Add typed** | `m.AddComponent(c)` / `m.AddBoundary(b)` / `m.AddDataFlow(f)` | `app.add_component(c)` etc. | `app.add_component(c)` etc. | `app.addComponent(c)` etc. |
| **Add dispatcher** | `m.Add(item any) error` | `app.add(item)` | `app.add(item)` | `app.add(item)` |
| **Analyze** | `m.Analyze() ([]*Threat, error)` | `app.analyze() -> list[Threat]` | `app.analyze() -> Result<Vec<Threat>>` | `app.analyze() -> Threat[]` |
| **Threat string** | `t.String()` | `str(t)` | `t.to_string()` | `t.toString()` |

## Per-Language Naming Notes

The canonical field names in this spec may use a different identifier in each port, either because of language keywords or because of casing conventions.

| Canonical field | Go (PascalCase) | Python (snake_case) | Rust (snake_case) | TypeScript (camelCase) |
|-----------------|-----------------|---------------------|-------------------|------------------------|
| `type` | `Type` | `component_type` | `component_type` | `type` |
| `data_types` | `DataTypes` | `data_types` | `data_types` | `dataTypes` |
| `environment` | `Environment` | `environment` | `environment` | `environment` |
| `stores` | `Stores` | `stores` | `stores` | `stores` |
| `handles` | `Handles` | `handles` | `handles` | `handles` |

`component_type` is used in Python and Rust because `type` is a built-in/keyword. All other fields follow each language's normal casing convention.

## Add API

All four implementations support these methods on `Model`:

- `add_component(component) / AddComponent` / `add_component`
- `add_boundary(boundary) / AddBoundary` / `add_boundary`
- `add_data_flow(flow) / AddDataFlow` / `add_data_flow`
- `analyze() -> Threat[]` / `[]*Threat` / `Result<Vec<Threat>>`

The `add` dispatcher is supported in Python (`model.add(item)`), TypeScript (`model.add(item)`), Rust (`model.add(item)`), and Go (`model.Add(item any) error`).

## Trust-Boundary Crossing Semantics

A data flow is considered to cross a trust boundary when, for any boundary:

- One endpoint is inside the boundary (`contains`) and the other is explicitly trusted across it (`trusts`), or
- Exactly one endpoint is inside the boundary (`contains`).

`contains` means the component is inside the boundary's zone. `trusts` means the boundary considers that component reachable and therefore exposed to whatever is on the other side of the boundary. This allows modeling nested or chained boundaries such as `internet -> dmz -> internal`.

## Validation

All implementations must validate:

- IDs are non-empty and unique within their collection.
- Data flow source and target exist and are not the same component.
- Boundary `contains` and `trusts` reference existing components.

Validation may happen at `analyze()` time or at addition time, but it must produce clear, actionable errors.

## Versioning

All four language ports share the same `MAJOR.MINOR.PATCH` version number. Releases are cut for all ports together, even if a specific port has no code changes, so consumers can rely on consistent cross-language behavior. Version bumps follow [Semantic Versioning](https://semver.org/):

- **MAJOR** — breaking API or behavior changes.
- **MINOR** — new features, new STRIDE categories, or significant analysis-rule changes.
- **PATCH** — bug fixes, documentation updates, or per-language idiomatic cleanups.

The canonical version lives in the root `README.md` and the per-language package manifests (`go.mod`, `pyproject.toml`, `Cargo.toml`, `package.json`).

## Future Additions

- Component-level `controls` to enable `Mitigated` statuses for component threats.
- JSON/YAML serialization for model exchange between languages.
- CLI reporter and SARIF output.
- Risk scoring (DREAD, CVSS) as an optional add-on.
