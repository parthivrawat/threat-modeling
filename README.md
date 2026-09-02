# Threat Modeling as Code

A multi-language **Threat Modeling as Code** library. Express systems as
components, trust boundaries, and data flows, then analyze them with the
**STRIDE** methodology to get actionable, version-controlled mitigations.

## What is Threat Modeling as Code?

Traditional threat models live in diagrams and documents that drift out of sync
with the system. This library lets you define your architecture in code, so your
threat model can be:

- Stored in version control alongside the architecture
- Re-analyzed automatically in CI/CD
- Shared consistently across teams and languages

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

## Languages

| Language     | Package / Module                                                            | README                         |
|--------------|------------------------------------------------------------------------------|--------------------------------|
| **Go**       | `github.com/parthivrawat/threat-modeling/go`                                 | [Go README](go/README.md)      |
| **Python**   | `pip install threat-modeling-py`                                             | [Python README](python/README.md) |
| **TypeScript** | `npm install threat-modeling-ts`                                           | [TypeScript README](typescript/README.md) |

## Quick Example

```python
from threat_modeling import Model, Component, Boundary

app = Model('payment-api')
app.add(Component('api', component_type='api', environment='k8s',
                  stores=['user-data'], exposed=True))
app.add(Boundary('internet', untrusted=True, trusts=['api']))

for threat in app.analyze():
    print(threat.kind, threat.target)
    for mitigation in threat.mitigations:
        print('  -', mitigation)
```

Equivalent examples are available in the [Go](go/README.md#quick-start),
[Python](python/README.md#quick-start), and
[TypeScript](typescript/README.md#quick-start) READMEs.

## Repository Layout

```
implementations/security/threat-modeling/
├── go/            # Go package (pkg.go.dev)
├── python/        # Python package (PyPI)
├── typescript/    # TypeScript package (NPM)
├── CHANGELOG.md   # Per-language changelogs are in each language directory
└── README.md      # This file
```

## License

MIT License
