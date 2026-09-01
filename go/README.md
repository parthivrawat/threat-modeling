# Threat Modeling as Code (Go)

A declarative threat-modeling library for Go. Express your system as
components, trust boundaries, and data flows, then analyze it with the STRIDE
methodology to get actionable, version-controlled mitigations.

## Features

- Declarative `Model`, `Component`, `Boundary`, and `DataFlow` types
- STRIDE threat classification: **Spoofing**, **Tampering**, **Repudiation**, **Information Disclosure**, **Denial of Service**, **Elevation of Privilege**
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

## Development

```bash
cd implementations/security/threat-modeling/go
go mod tidy
go test ./...
go build ./...
```

## Publishing to pkg.go.dev

1. Commit the `go/` directory to a public Git repository at `github.com/parthivrawat/threat-modeling`.
2. Push a version tag using the `go/` prefix:

```bash
git tag go/v1.0.0
git push origin go/v1.0.0
```

3. pkg.go.dev will index the package automatically. Visit:

```
https://pkg.go.dev/github.com/parthivrawat/threat-modeling/go@v1.0.0
```

## License

MIT License
