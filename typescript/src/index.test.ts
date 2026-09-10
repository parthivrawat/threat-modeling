import { describe, it, expect } from 'vitest';
import { Boundary, Component, DataFlow, Model, Threat, ThreatKind, ThreatStatus } from './index';

describe('Component', () => {
  it('applies defaults', () => {
    const c = new Component('api');
    expect(c.id).toBe('api');
    expect(c.name).toBe('api');
    expect(c.type).toBe('service');
    expect(c.stores).toEqual([]);
    expect(c.handles).toEqual([]);
  });

  it('uses the runsIn alias for environment', () => {
    const c = new Component('api', undefined, { runsIn: 'k8s' });
    expect(c.environment).toBe('k8s');
  });
});

describe('Model.analyze', () => {
  it('produces all STRIDE component threats for a payment API', () => {
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

    const threats = app.analyze();
    expect(threats.length).toBeGreaterThan(0);

    const found = new Set(threats.filter((t) => t.target === 'api').map((t) => t.kind));
    for (const kind of Object.values(ThreatKind)) {
      expect(found).toContain(kind);
    }
  });

  it('produces data flow threats for sensitive data', () => {
    const app = new Model('web-shop');
    app.add(new Component('browser', 'Browser', { type: 'browser' }));
    app.add(new Component('api', 'API', { type: 'api', environment: 'k8s', exposed: true }));
    app.add(
      new Boundary('internet', 'Internet', {
        untrusted: true,
        contains: ['browser'],
        trusts: ['api'],
      }),
    );
    app.add(
      new DataFlow('login', 'browser', 'api', {
        protocol: 'https',
        auth: 'bearer',
        dataTypes: ['credentials'],
      }),
    );

    const threats = app.analyze();
    expect(threats.some((t) => t.target === 'login' && t.kind === ThreatKind.InformationDisclosure)).toBe(true);
  });

  it('marks flow threats as Mitigated when controls are in place', () => {
    const app = new Model('secure-flow');
    app.add(new Component('a'));
    app.add(new Component('b'));
    app.add(
      new DataFlow('f', 'a', 'b', {
        protocol: 'https',
        auth: 'bearer',
      }),
    );

    const threats = app.analyze();
    const byKind = new Map(
      threats.filter((t) => t.target === 'f').map((t) => [t.kind, t.status]),
    );
    expect(byKind.get(ThreatKind.Spoofing)).toBe(ThreatStatus.Mitigated);
    expect(byKind.get(ThreatKind.Tampering)).toBe(ThreatStatus.Mitigated);
    expect(byKind.get(ThreatKind.InformationDisclosure)).toBe(ThreatStatus.Mitigated);
    expect(byKind.get(ThreatKind.ElevationOfPrivilege)).toBe(ThreatStatus.Mitigated);
    expect(byKind.get(ThreatKind.Repudiation)).toBe(ThreatStatus.Open);
    expect(byKind.get(ThreatKind.DenialOfService)).toBe(ThreatStatus.Open);
  });

  it('keeps flow threats Open when controls are missing or data is sensitive', () => {
    const app = new Model('insecure-flow');
    app.add(new Component('a'));
    app.add(new Component('b'));
    app.add(new DataFlow('f', 'a', 'b', { dataTypes: ['credentials'] }));

    const threats = app.analyze();
    for (const t of threats.filter((t) => t.target === 'f')) {
      expect(t.status).toBe(ThreatStatus.Open);
    }
  });

  it('defaults component threats and Threat constructor to Open', () => {
    const app = new Model('comps');
    app.add(new Component('api', 'API', { type: 'api', stores: ['pii'] }));
    const threats = app.analyze();
    for (const t of threats) {
      expect(t.status).toBe(ThreatStatus.Open);
    }
    const t = new Threat(ThreatKind.Spoofing, 'api', 'desc');
    expect(t.status).toBe(ThreatStatus.Open);
  });

  it('validates unknown components in boundaries', () => {
    const app = new Model('bad-boundary');
    app.add(new Component('a'));
    expect(() => app.addBoundary(new Boundary('b', undefined, { contains: ['missing'] }))).toThrow(
      /references unknown component/,
    );
  });

  it('validates unknown flow targets', () => {
    const app = new Model('bad-flow');
    app.add(new Component('a'));
    expect(() => app.addDataFlow(new DataFlow('f', 'a', 'missing'))).toThrow(/unknown target/);
  });

  it('treats data types case-insensitively', () => {
    const app = new Model('case-insensitive');
    app.add(new Component('a'));
    app.add(new Component('b'));
    app.addDataFlow(new DataFlow('f', 'a', 'b', { dataTypes: ['PII'] }));

    const threats = app.analyze();
    const info = threats.find(
      (t) => t.target === 'f' && t.kind === ThreatKind.InformationDisclosure,
    );
    expect(info).toBeDefined();
    expect(info!.mitigations).toContain('Mask or tokenize sensitive data fields');
  });

  it('rejects duplicate components', () => {
    const app = new Model('dup');
    const c = new Component('a');
    app.add(c);
    expect(() => app.add(c)).toThrow(/already exists/);
  });

  it('detects nested boundary crossings', () => {
    const app = new Model('nested');
    app.add(new Component('browser', 'Browser'));
    app.add(new Component('api', 'API', { type: 'api' }));
    app.add(new Component('db', 'Database', { type: 'database' }));
    app.add(
      new Boundary('internet', 'Internet', {
        untrusted: true,
        contains: ['browser'],
        trusts: ['api'],
      }),
    );
    app.add(
      new Boundary('dmz', 'DMZ', {
        contains: ['api'],
        trusts: ['db'],
      }),
    );
    const browserApi = new DataFlow('browser-api', 'browser', 'api');
    const apiDb = new DataFlow('api-db', 'api', 'db');
    app.add(browserApi);
    app.add(apiDb);

    expect((app as any).flowCrossesBoundary(browserApi)).toBe(true);
    expect((app as any).flowCrossesBoundary(apiDb)).toBe(true);
  });

  it('sorts threats by target', () => {
    const app = new Model('sorted');
    app.add(new Component('b', undefined, { stores: ['user-data'] }));
    app.add(new Component('a', undefined, { stores: ['user-data'] }));
    const threats = app.analyze();
    expect(threats[0].target).toBe('a');
  });

  it('always returns threats or fails validation for random models', () => {
    const makeApp = (n: number) => new Model(`random-${n}`);

    const cases = [
      () => {
        const app = makeApp(0);
        app.add(new Component('api', undefined, { type: 'api', exposed: true }));
        app.add(new Component('db', undefined, { stores: ['user-data'] }));
        app.add(new DataFlow('api-db', 'api', 'db', { dataTypes: ['pii'] }));
        return app;
      },
      () => {
        const app = makeApp(1);
        app.add(new Component('browser', 'Browser'));
        app.add(new Component('api', 'API', { type: 'api', exposed: true }));
        app.add(new DataFlow('login', 'browser', 'api', { dataTypes: ['credentials'] }));
        return app;
      },
      () => {
        const app = makeApp(2);
        app.add(new Component('svc', 'Service', { type: 'service', stores: ['pii'] }));
        app.add(new Component('queue', 'Queue', { type: 'queue' }));
        app.add(new DataFlow('svc-queue', 'svc', 'queue', { dataTypes: ['pii'] }));
        return app;
      },
      () => {
        const app = makeApp(3);
        app.add(new Component('mobile', 'Mobile App', { type: 'mobile' }));
        app.add(new Component('api', 'API', { type: 'api', exposed: true, stores: ['health-data'] }));
        app.add(new DataFlow('sync', 'mobile', 'api', { dataTypes: ['pii'], auth: 'oauth' }));
        return app;
      },
      () => {
        const app = makeApp(4);
        app.add(new Component('a'));
        app.addDataFlow(new DataFlow('bad', 'a', 'missing', { dataTypes: ['pii'] }));
        return app;
      },
    ];

    for (let i = 0; i < cases.length - 1; i++) {
      const app = cases[i]();
      const threats = app.analyze();
      expect(threats.length).toBeGreaterThan(0);
      for (const threat of threats) {
        expect(threat.target).toBeDefined();
        expect(threat.kind).toBeDefined();
      }
    }

    expect(() => cases[cases.length - 1]()).toThrow(/unknown target/);
  });
});

describe('Threat', () => {
  it('serializes to a readable string', () => {
    const t = new Threat(ThreatKind.Spoofing, 'api', 'desc', []);
    expect(t.toString()).toBe('Spoofing on api');
  });
});
