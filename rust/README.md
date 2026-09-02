# Threat Modeling as Code (Rust)

A declarative, code-first threat-modeling library for Rust. Express your system as
components, trust boundaries, and data flows, then analyze it with the **STRIDE**
methodology to get actionable, version-controlled mitigations.

## Features

- Declarative `Model`, `Component`, `Boundary`, and `DataFlow` types
- **STRIDE** threat classification:
  - Spoofing
  - Tampering
  - Repudiation
  - Information Disclosure
  - Denial of Service
  - Elevation of Privilege
- Trust-boundary-aware data flow analysis
- Built-in, context-aware mitigation catalog
- Zero runtime dependencies
- Builder API for ergonomic model construction

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
threat-modeling-rs = "1.0.0"
```

## Quick Start

```rust
use threat_modeling_rs::{Boundary, Component, DataFlow, Model};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = Model::new("payment-api");
    app.add_component(
        Component::new("api")
            .name("Payment API")
            .component_type("api")
            .environment("k8s")
            .stores(&["user-data"])
            .exposed(true),
    );
    app.add_boundary(Boundary::new("internet").untrusted(true).trusts(&["api"]));
    app.add_data_flow(
        DataFlow::new("request", "browser", "api")
            .protocol("https")
            .auth("bearer")
            .data_types(&["payment-card"]),
    );

    let threats = app.analyze()?;
    for threat in threats {
        println!("{} - {}", threat.kind, threat.target);
        for mitigation in &threat.mitigations {
            println!("  - {}", mitigation);
        }
    }

    Ok(())
}
```

## Core Concepts

- `Model` — the top-level container for components, boundaries, and data flows.
- `Component` — a service, API, database, browser, or any architectural element.
- `Boundary` — a trust boundary; `untrusted` marks external zones such as the internet.
- `DataFlow` — a directed interaction between two components.
- `Threat` — a `STRIDE` finding with a target, description, and list of mitigations.

## Why Threat Modeling as Code?

- **Version control:** threat models live in the same repo as the architecture.
- **Automation:** run `analyze()` in CI to catch changes in risk posture.
- **Consistency:** use the same model across languages and teams.

## Cross-Language Support

This library is also available for [Go](../go/README.md) and [Python](../python/README.md) and [TypeScript](../typescript/README.md).

## Development

```bash
cd implementations/security/threat-modeling/rust
cargo build
cargo test
```

## License

MIT License
