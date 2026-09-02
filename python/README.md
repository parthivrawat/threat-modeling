# Threat Modeling as Code (Python)

A declarative threat-modeling library for Python. Express your system as
components, trust boundaries, and data flows, then analyze it with the STRIDE
methodology to get actionable, version-controlled mitigations.

## Features

- Declarative `Model`, `Component`, `Boundary`, and `DataFlow` types
- STRIDE threat classification: **Spoofing**, **Tampering**, **Repudiation**, **Information Disclosure**, **Denial of Service**, **Elevation of Privilege**
- Trust-boundary-aware data flow analysis
- Built-in, context-aware mitigation catalog
- Zero runtime dependencies
- Type hints included (`py.typed`)

## Installation

```bash
pip install threat-modeling-py
```

## Quick Start

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

## Development

```bash
cd implementations/security/threat-modeling/python
pip install -e ".[dev]"
pytest test_threat_modeling.py -v
```

## Publishing to PyPI

```bash
cd implementations/security/threat-modeling/python
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

## License

MIT License
