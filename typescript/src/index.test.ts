import { describe, it, expect } from 'vitest';
import { Boundary, Component, DataFlow, Model, Threat, ThreatKind } from './index';

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

  it('validates unknown components in boundaries', () => {
    const app = new Model('bad-boundary');
    app.add(new Component('a'));
    app.add(new Boundary('b', undefined, { contains: ['missing'] }));
    expect(() => app.analyze()).toThrow(/contains unknown component/);
  });

  it('validates unknown flow targets', () => {
    const app = new Model('bad-flow');
    app.add(new Component('a'));
    app.add(new DataFlow('f', 'a', 'missing'));
    expect(() => app.analyze()).toThrow(/unknown target/);
  });

  it('rejects duplicate components', () => {
    const app = new Model('dup');
    const c = new Component('a');
    app.add(c);
    expect(() => app.add(c)).toThrow(/already exists/);
  });

  it('sorts threats by target', () => {
    const app = new Model('sorted');
    app.add(new Component('b'));
    app.add(new Component('a'));
    const threats = app.analyze();
    expect(threats[0].target).toBe('a');
  });
});

describe('Threat', () => {
  it('serializes to a readable string', () => {
    const t = new Threat(ThreatKind.Spoofing, 'api', 'desc', []);
    expect(t.toString()).toBe('Spoofing on api');
  });
});
