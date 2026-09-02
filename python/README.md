# Threat Modeling as Code (Python)

A declarative, code-first threat-modeling library for Python. Express your system as
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
- Type hints included (`py.typed`)
- Supports Python 3.8+

## Installation

```bash
pip install threat-modeling-py
```

## Quick Start

```python
from threat_modeling import Model, Component, Boundary, DataFlow

app = Model('payment-api')
app.add(Component('api', component_type='api', environment='k8s',
                  stores=['user-data'], exposed=True))
app.add(Boundary('internet', untrusted=True, trusts=['api']))
app.add(DataFlow('request', 'browser', 'api', protocol='https',
                 auth='bearer', data_types=['payment-card']))

for threat in app.analyze():
    print(threat.kind, '-', threat.target)
    for mitigation in threat.mitigations:
        print('  -', mitigation)
```

## Core Concepts

- `Model` — the top-level container for components, boundaries, and data flows.
- `Component` — a service, API, database, browser, or any architectural element.
- `Boundary` — a trust boundary; `untrusted=True` marks external zones such as the internet.
- `DataFlow` — a directed interaction between two components.
- `Threat` — a `STRIDE` finding with a target, description, and list of mitigations.

## Why Threat Modeling as Code?

- **Version control:** threat models live in the same repo as the architecture.
- **Automation:** run `analyze()` in CI to catch changes in risk posture.
- **Consistency:** use the same model across languages and teams.

## Cross-Language Support

This library is also available for [Go](../go/README.md), [TypeScript](../typescript/README.md), and [Rust](../rust/README.md).

## Development

```bash
cd implementations/security/threat-modeling/python
pip install -e ".[dev]"
pytest test_threat_modeling.py -v
```

## License

MIT License
