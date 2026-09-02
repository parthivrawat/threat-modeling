# Threat Modeling as Code (TypeScript)

A declarative, code-first threat-modeling library for TypeScript/Node.js. Express
your system as components, trust boundaries, and data flows, then analyze it with
the **STRIDE** methodology to get actionable, version-controlled mitigations.

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
- Dual CommonJS/ESM exports
- Node.js 18+

## Installation

```bash
npm install threat-modeling-ts
```

## Quick Start

```typescript
import { Model, Component, Boundary, DataFlow } from 'threat-modeling-ts';

const app = new Model('payment-api');
app.add(
  new Component('api', 'Payment API', {
    type: 'api',
    environment: 'k8s',
    stores: ['user-data'],
    exposed: true,
  }),
);
app.add(new Boundary('internet', 'Internet', { untrusted: true, trusts: ['api'] }));
app.add(
  new DataFlow('request', 'browser', 'api', {
    protocol: 'https',
    auth: 'bearer',
    dataTypes: ['payment-card'],
  }),
);

for (const threat of app.analyze()) {
  console.log(threat.kind, '-', threat.target);
  for (const mitigation of threat.mitigations) {
    console.log('  -', mitigation);
  }
}
```

## Core Concepts

- `Model` — the top-level container for components, boundaries, and data flows.
- `Component` — a service, API, database, browser, or any architectural element.
- `Boundary` — a trust boundary; `untrusted: true` marks external zones such as the internet.
- `DataFlow` — a directed interaction between two components.
- `Threat` — a `STRIDE` finding with a target, description, and list of mitigations.

## Why Threat Modeling as Code?

- **Version control:** threat models live in the same repo as the architecture.
- **Automation:** run `analyze()` in CI to catch changes in risk posture.
- **Consistency:** use the same model across languages and teams.

## Cross-Language Support

This library is also available for [Go](../go/README.md) and [Python](../python/README.md).

## Development

```bash
cd implementations/security/threat-modeling/typescript
npm install
npm run build
npm test
```

## License

MIT License
