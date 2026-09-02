# Threat Modeling as Code (Go)

A declarative, code-first threat-modeling library for Go. Express your system as
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
- Goroutine-safe
- Ready for [pkg.go.dev](https://pkg.go.dev)

## Installation

```bash
go get github.com/parthivrawat/threat-modeling/go@latest
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/parthivrawat/threat-modeling/go"
)

func main() {
    m := threatmodel.New("payment-api")

    if err := m.AddComponent(threatmodel.NewComponent("api", "Payment API", threatmodel.ComponentOpts{
        Type:        "api",
        Environment: "k8s",
        Stores:      []string{"user-data"},
        Exposed:     true,
    })); err != nil {
        log.Fatal(err)
    }

    if err := m.AddBoundary(threatmodel.NewBoundary("internet", "Internet", threatmodel.BoundaryOpts{
        Untrusted: true,
        Trusts:    []string{"api"},
    })); err != nil {
        log.Fatal(err)
    }

    if err := m.AddDataFlow(threatmodel.NewDataFlow("request", "browser", "api", threatmodel.FlowOpts{
        Protocol:  "https",
        Auth:      "bearer",
        DataTypes: []string{"payment-card"},
    })); err != nil {
        log.Fatal(err)
    }

    threats, err := m.Analyze()
    if err != nil {
        log.Fatal(err)
    }

    for _, t := range threats {
        fmt.Println(t.Kind, "-", t.Target)
        for _, mitigation := range t.Mitigations {
            fmt.Println("  -", mitigation)
        }
    }
}
```

## Core Concepts

- `Model` — the top-level container for components, boundaries, and data flows.
- `Component` — a service, API, database, browser, or any architectural element.
- `Boundary` — a trust boundary; `Untrusted` marks external zones such as the internet.
- `DataFlow` — a directed interaction between two components.
- `Threat` — a `STRIDE` finding with a target, description, and list of mitigations.

## Why Threat Modeling as Code?

- **Version control:** threat models live in the same repo as the architecture.
- **Automation:** run `Analyze()` in CI to catch changes in risk posture.
- **Consistency:** use the same model across languages and teams.

## Cross-Language Support

This library is also available for [Python](../python/README.md) and [TypeScript](../typescript/README.md).

## Development

```bash
cd implementations/security/threat-modeling/go
go mod tidy
go test ./...
go build ./...
```

## License

MIT License
