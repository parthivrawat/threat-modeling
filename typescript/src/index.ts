export enum ThreatKind {
  Spoofing = 'Spoofing',
  Tampering = 'Tampering',
  Repudiation = 'Repudiation',
  InformationDisclosure = 'InformationDisclosure',
  DenialOfService = 'DenialOfService',
  ElevationOfPrivilege = 'ElevationOfPrivilege',
}

export class Threat {
  constructor(
    public readonly kind: ThreatKind,
    public readonly target: string,
    public readonly description: string,
    public readonly mitigations: string[] = [],
  ) {}

  toString(): string {
    return `${this.kind} on ${this.target}`;
  }
}

export interface ComponentOptions {
  type?: string;
  environment?: string;
  runsIn?: string;
  stores?: string[];
  handles?: string[];
  exposed?: boolean;
}

export class Component {
  readonly id: string;
  readonly name: string;
  readonly type: string;
  readonly environment: string;
  readonly stores: string[];
  readonly handles: string[];
  readonly exposed: boolean;

  constructor(id: string, name?: string, options: ComponentOptions = {}) {
    this.id = id;
    this.name = name ?? id;
    this.type = options.type ?? 'service';
    this.environment = options.environment ?? options.runsIn ?? '';
    this.stores = options.stores ? [...options.stores] : [];
    this.handles = options.handles ? [...options.handles] : [];
    this.exposed = options.exposed ?? false;
  }
}

export interface BoundaryOptions {
  untrusted?: boolean;
  contains?: string[];
  trusts?: string[];
}

export class Boundary {
  readonly id: string;
  readonly name: string;
  readonly untrusted: boolean;
  readonly contains: string[];
  readonly trusts: string[];

  constructor(id: string, name?: string, options: BoundaryOptions = {}) {
    this.id = id;
    this.name = name ?? id;
    this.untrusted = options.untrusted ?? false;
    this.contains = options.contains ? [...options.contains] : [];
    this.trusts = options.trusts ? [...options.trusts] : [];
  }
}

export interface DataFlowOptions {
  protocol?: string;
  auth?: string;
  dataTypes?: string[];
}

export class DataFlow {
  readonly id: string;
  readonly source: string;
  readonly target: string;
  readonly protocol: string;
  readonly auth: string;
  readonly dataTypes: string[];

  constructor(id: string, source: string, target: string, options: DataFlowOptions = {}) {
    this.id = id;
    this.source = source;
    this.target = target;
    this.protocol = options.protocol ?? '';
    this.auth = options.auth ?? '';
    this.dataTypes = options.dataTypes ? [...options.dataTypes] : [];
  }
}

export type ModelItem = Component | Boundary | DataFlow;

const SENSITIVE_DATA_TYPES: Set<string> = new Set([
  'user-data',
  'pii',
  'payment-card',
  'credentials',
  'financial',
  'health',
  'password',
  'secret',
  'token',
]);

const SECURE_PROTOCOLS: Set<string> = new Set(['https', 'tls', 'mtls', 'ssh']);

function flowHasSensitiveData(flow: DataFlow): boolean {
  return flow.dataTypes.some((d) => SENSITIVE_DATA_TYPES.has(d));
}

function isSecureProtocol(protocol: string): boolean {
  return SECURE_PROTOCOLS.has(protocol.toLowerCase());
}

function componentThreats(component: Component, exposed: boolean): Threat[] {
  const threats: Threat[] = [];
  const hasData = component.stores.length > 0 || component.handles.length > 0;

  if (exposed || component.type === 'api' || component.type === 'gateway' || component.type === 'load-balancer') {
    threats.push(
      new Threat(
        ThreatKind.Spoofing,
        component.id,
        `${component.name} may be spoofed by an attacker`,
        [
          'Enforce strong authentication and caller identity verification',
          'Use mutual TLS or service identity tokens',
        ],
      ),
    );
  }

  if (hasData) {
    threats.push(
      new Threat(
        ThreatKind.Tampering,
        component.id,
        `${component.name} processes or stores data that could be tampered with`,
        [
          'Validate and sanitize all inputs',
          'Use integrity checks such as checksums or signatures',
          'Restrict write access to authorized actors',
        ],
      ),
    );
  }

  if (hasData) {
    threats.push(
      new Threat(
        ThreatKind.Repudiation,
        component.id,
        `Actions on ${component.name} may not be provably logged`,
        [
          'Implement immutable audit logging',
          'Include non-repudiable timestamps and identities',
          'Protect logs from tampering',
        ],
      ),
    );
  }

  if (hasData) {
    threats.push(
      new Threat(
        ThreatKind.InformationDisclosure,
        component.id,
        `${component.name} may leak stored or processed data`,
        [
          'Encrypt data at rest and in transit',
          'Apply least-privilege and need-to-know access',
          'Mask, tokenize, or redact sensitive fields',
        ],
      ),
    );
  }

  if (exposed || component.type === 'api' || component.type === 'gateway' || component.type === 'load-balancer') {
    threats.push(
      new Threat(
        ThreatKind.DenialOfService,
        component.id,
        `${component.name} may be targeted by a denial-of-service attack`,
        [
          'Implement rate limiting and throttling',
          'Use DDoS protection, autoscaling, and load balancing',
          'Apply resource quotas and circuit breakers',
        ],
      ),
    );
  }

  if (
    component.environment === 'k8s' ||
    component.environment === 'container' ||
    component.environment === 'vm' ||
    component.type === 'api' ||
    component.type === 'service'
  ) {
    threats.push(
      new Threat(
        ThreatKind.ElevationOfPrivilege,
        component.id,
        `An attacker may gain unauthorized privileges on ${component.name}`,
        [
          'Apply least-privilege RBAC and service accounts',
          'Use sandboxed or isolated execution environments',
          'Regularly patch and harden host and container images',
        ],
      ),
    );
  }

  return threats;
}

function flowThreats(flow: DataFlow, crossing: boolean, sensitive: boolean): Threat[] {
  const base = `Data flow ${flow.id} from ${flow.source} to ${flow.target}`;
  const threats: Threat[] = [];

  const spoofMits = [
    'Validate the source identity before processing',
    'Use mutual TLS or signed tokens for callers',
  ];
  if (!flow.auth) {
    spoofMits.unshift('Require authentication for this flow');
  }
  threats.push(new Threat(ThreatKind.Spoofing, flow.id, `${base} may be spoofed`, spoofMits));

  const tampMits = [
    'Validate message integrity',
    'Use signed or MAC-protected payloads',
  ];
  if (!isSecureProtocol(flow.protocol)) {
    tampMits.unshift('Encrypt the channel with TLS');
  }
  threats.push(new Threat(ThreatKind.Tampering, flow.id, `${base} may be tampered with in transit`, tampMits));

  threats.push(
    new Threat(
      ThreatKind.Repudiation,
      flow.id,
      `${base} may not leave a non-repudiable audit trail`,
      [
        'Log all requests with source and target identities',
        'Protect logs from tampering',
        'Include non-repudiable timestamps',
      ],
    ),
  );

  const infoMits = [
    'Minimize data shared over this flow',
    'Apply field-level encryption or tokenization',
  ];
  if (!isSecureProtocol(flow.protocol)) {
    infoMits.unshift('Encrypt data in transit using TLS');
  }
  if (sensitive) {
    infoMits.unshift('Mask or tokenize sensitive data fields');
  }
  threats.push(new Threat(ThreatKind.InformationDisclosure, flow.id, `${base} may leak sensitive information`, infoMits));

  const dosMits = [
    'Implement rate limiting and throttling',
    'Use queues or load balancing to absorb spikes',
    'Apply per-source quotas',
  ];
  if (!crossing) {
    dosMits.push('Validate internal callers to prevent resource abuse');
  }
  threats.push(new Threat(ThreatKind.DenialOfService, flow.id, `${base} may be used to deny service`, dosMits));

  const eleMits = [
    'Authorize every request',
    'Validate caller privileges at the target',
    'Use least-privilege access for the target',
  ];
  if (!flow.auth) {
    eleMits.unshift('Enforce authentication before authorization');
  }
  threats.push(new Threat(ThreatKind.ElevationOfPrivilege, flow.id, `${base} may allow privilege escalation`, eleMits));

  return threats;
}

export class Model {
  readonly name: string;
  private readonly components = new Map<string, Component>();
  private readonly boundaries = new Map<string, Boundary>();
  private readonly flows = new Map<string, DataFlow>();

  constructor(name: string) {
    this.name = name;
  }

  add(item: ModelItem): void {
    if (item instanceof Component) {
      this.addComponent(item);
    } else if (item instanceof Boundary) {
      this.addBoundary(item);
    } else if (item instanceof DataFlow) {
      this.addDataFlow(item);
    } else {
      throw new TypeError('Unsupported item type');
    }
  }

  addComponent(component: Component): void {
    if (this.components.has(component.id)) {
      throw new Error(`Component ID already exists: ${component.id}`);
    }
    this.components.set(component.id, component);
  }

  addBoundary(boundary: Boundary): void {
    if (this.boundaries.has(boundary.id)) {
      throw new Error(`Boundary ID already exists: ${boundary.id}`);
    }
    this.boundaries.set(boundary.id, boundary);
  }

  addDataFlow(flow: DataFlow): void {
    if (this.flows.has(flow.id)) {
      throw new Error(`Data flow ID already exists: ${flow.id}`);
    }
    if (flow.source === flow.target) {
      throw new Error(`Data flow ${flow.id} is self-referential`);
    }
    this.flows.set(flow.id, flow);
  }

  analyze(): Threat[] {
    this.validate();
    const exposed = this.exposedComponents();
    const threats: Threat[] = [];

    const comps = Array.from(this.components.values()).sort((a, b) => a.id.localeCompare(b.id));
    for (const comp of comps) {
      threats.push(...componentThreats(comp, exposed.has(comp.id)));
    }

    const flows = Array.from(this.flows.values()).sort((a, b) => a.id.localeCompare(b.id));
    for (const flow of flows) {
      const crossing = this.flowCrossesBoundary(flow);
      const sensitive = flowHasSensitiveData(flow);
      threats.push(...flowThreats(flow, crossing, sensitive));
    }

    threats.sort((a, b) => {
      if (a.target === b.target) {
        return String(a.kind).localeCompare(String(b.kind));
      }
      return a.target.localeCompare(b.target);
    });

    return threats;
  }

  private validate(): void {
    for (const boundary of this.boundaries.values()) {
      for (const componentId of boundary.contains) {
        if (!this.components.has(componentId)) {
          throw new Error(`Boundary ${boundary.id} contains unknown component ${componentId}`);
        }
      }
      for (const componentId of boundary.trusts) {
        if (!this.components.has(componentId)) {
          throw new Error(`Boundary ${boundary.id} trusts unknown component ${componentId}`);
        }
      }
    }

    for (const flow of this.flows.values()) {
      if (!this.components.has(flow.source)) {
        throw new Error(`Data flow ${flow.id} has unknown source ${flow.source}`);
      }
      if (!this.components.has(flow.target)) {
        throw new Error(`Data flow ${flow.id} has unknown target ${flow.target}`);
      }
    }
  }

  private exposedComponents(): Set<string> {
    const exposed = new Set<string>();
    for (const [id, component] of this.components) {
      if (component.exposed) {
        exposed.add(id);
      }
    }
    for (const boundary of this.boundaries.values()) {
      if (boundary.untrusted) {
        for (const componentId of boundary.contains) {
          exposed.add(componentId);
        }
        for (const componentId of boundary.trusts) {
          exposed.add(componentId);
        }
      }
    }
    return exposed;
  }

  private flowCrossesBoundary(flow: DataFlow): boolean {
    for (const boundary of this.boundaries.values()) {
      const srcContains = boundary.contains.includes(flow.source);
      const dstContains = boundary.contains.includes(flow.target);
      const srcTrusts = boundary.trusts.includes(flow.source);
      const dstTrusts = boundary.trusts.includes(flow.target);

      if ((srcContains && dstTrusts) || (srcTrusts && dstContains)) {
        return true;
      }
      if (srcContains !== dstContains) {
        return true;
      }
    }
    return false;
  }
}
