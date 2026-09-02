//! Threat Modeling as Code (Rust)
//!
//! A declarative STRIDE threat-modeling library. Express systems as components,
//! trust boundaries, and data flows, then analyze them to get targeted
//! mitigations.

use std::collections::{HashMap, HashSet};
use std::fmt;

/// A STRIDE threat category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThreatKind {
    /// Identity deception and impersonation.
    Spoofing,
    /// Unauthorized modification of data or code.
    Tampering,
    /// Inability to prove that an action occurred.
    Repudiation,
    /// Unintended data exposure.
    InformationDisclosure,
    /// Availability attacks and resource exhaustion.
    DenialOfService,
    /// Gaining unauthorized capabilities.
    ElevationOfPrivilege,
}

impl fmt::Display for ThreatKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatKind::Spoofing => write!(f, "Spoofing"),
            ThreatKind::Tampering => write!(f, "Tampering"),
            ThreatKind::Repudiation => write!(f, "Repudiation"),
            ThreatKind::InformationDisclosure => write!(f, "InformationDisclosure"),
            ThreatKind::DenialOfService => write!(f, "DenialOfService"),
            ThreatKind::ElevationOfPrivilege => write!(f, "ElevationOfPrivilege"),
        }
    }
}

/// A single identified threat and its recommended mitigations.
#[derive(Debug, Clone)]
pub struct Threat {
    /// The STRIDE category.
    pub kind: ThreatKind,
    /// The component or data flow that is targeted.
    pub target: String,
    /// A human-readable description of the threat.
    pub description: String,
    /// Recommended mitigations.
    pub mitigations: Vec<String>,
}

impl Threat {
    /// Create a new threat.
    pub fn new(
        kind: ThreatKind,
        target: impl Into<String>,
        description: impl Into<String>,
        mitigations: Vec<String>,
    ) -> Self {
        Self {
            kind,
            target: target.into(),
            description: description.into(),
            mitigations,
        }
    }
}

impl fmt::Display for Threat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on {}", self.kind, self.target)
    }
}

/// Errors that can occur while building or analyzing a threat model.
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatModelError {
    /// A duplicate identifier was used.
    DuplicateId(String),
    /// A data flow references itself.
    SelfReferentialFlow(String),
    /// A referenced component does not exist.
    UnknownComponent {
        /// The identifier that was not found.
        reference: String,
        /// Where the reference was made.
        context: String,
    },
}

impl fmt::Display for ThreatModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatModelError::DuplicateId(id) => write!(f, "duplicate ID: {id}"),
            ThreatModelError::SelfReferentialFlow(id) => write!(f, "data flow {id} is self-referential"),
            ThreatModelError::UnknownComponent { reference, context } => {
                write!(f, "{context}: unknown component {reference}")
            }
        }
    }
}

impl std::error::Error for ThreatModelError {}

/// An architectural component such as an API, database, service, or browser.
#[derive(Debug, Clone)]
pub struct Component {
    /// The component identifier.
    pub id: String,
    /// A human-readable name; defaults to `id`.
    pub name: String,
    /// The kind of component, e.g. "api", "service", "database".
    pub component_type: String,
    /// The runtime environment, e.g. "k8s", "vm", "browser".
    pub environment: String,
    /// Data types that the component stores.
    pub stores: Vec<String>,
    /// Data types that the component handles.
    pub handles: Vec<String>,
    /// Whether the component is exposed to untrusted actors.
    pub exposed: bool,
}

impl Component {
    /// Create a new component with the given identifier.
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            name: id.clone(),
            id,
            component_type: "service".to_string(),
            environment: String::new(),
            stores: Vec::new(),
            handles: Vec::new(),
            exposed: false,
        }
    }

    /// Set the human-readable name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set the component type.
    pub fn component_type(mut self, component_type: impl Into<String>) -> Self {
        self.component_type = component_type.into();
        self
    }

    /// Set the runtime environment.
    pub fn environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = environment.into();
        self
    }

    /// Alias for [`Self::environment`].
    pub fn runs_in(mut self, environment: impl Into<String>) -> Self {
        self.environment = environment.into();
        self
    }

    /// Set the data types this component stores.
    pub fn stores(mut self, stores: &[&str]) -> Self {
        self.stores = stores.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set the data types this component handles.
    pub fn handles(mut self, handles: &[&str]) -> Self {
        self.handles = handles.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Mark the component as exposed to untrusted actors.
    pub fn exposed(mut self, exposed: bool) -> Self {
        self.exposed = exposed;
        self
    }
}

/// A trust boundary that separates components.
#[derive(Debug, Clone)]
pub struct Boundary {
    /// The boundary identifier.
    pub id: String,
    /// A human-readable name; defaults to `id`.
    pub name: String,
    /// Whether the boundary is an untrusted, external zone such as the internet.
    pub untrusted: bool,
    /// Component identifiers inside the boundary.
    pub contains: Vec<String>,
    /// Component identifiers explicitly trusted across the boundary.
    pub trusts: Vec<String>,
}

impl Boundary {
    /// Create a new boundary with the given identifier.
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            name: id.clone(),
            id,
            untrusted: false,
            contains: Vec::new(),
            trusts: Vec::new(),
        }
    }

    /// Set the human-readable name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Mark the boundary as untrusted.
    pub fn untrusted(mut self, untrusted: bool) -> Self {
        self.untrusted = untrusted;
        self
    }

    /// Set the component identifiers inside the boundary.
    pub fn contains(mut self, contains: &[&str]) -> Self {
        self.contains = contains.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set the component identifiers this boundary trusts.
    pub fn trusts(mut self, trusts: &[&str]) -> Self {
        self.trusts = trusts.iter().map(|s| s.to_string()).collect();
        self
    }
}

/// A directed interaction between two components.
#[derive(Debug, Clone)]
pub struct DataFlow {
    /// The flow identifier.
    pub id: String,
    /// The source component identifier.
    pub source: String,
    /// The target component identifier.
    pub target: String,
    /// The protocol used, e.g. "https".
    pub protocol: String,
    /// The authentication mechanism, e.g. "bearer".
    pub auth: String,
    /// Data types carried by the flow.
    pub data_types: Vec<String>,
}

impl DataFlow {
    /// Create a new data flow from source to target.
    pub fn new(
        id: impl Into<String>,
        source: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            source: source.into(),
            target: target.into(),
            protocol: String::new(),
            auth: String::new(),
            data_types: Vec::new(),
        }
    }

    /// Set the protocol.
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = protocol.into();
        self
    }

    /// Set the authentication mechanism.
    pub fn auth(mut self, auth: impl Into<String>) -> Self {
        self.auth = auth.into();
        self
    }

    /// Set the data types carried by the flow.
    pub fn data_types(mut self, data_types: &[&str]) -> Self {
        self.data_types = data_types.iter().map(|s| s.to_string()).collect();
        self
    }
}

/// The top-level threat model container.
#[derive(Debug, Clone)]
pub struct Model {
    /// The model name.
    pub name: String,
    components: HashMap<String, Component>,
    boundaries: HashMap<String, Boundary>,
    flows: HashMap<String, DataFlow>,
}

impl Model {
    /// Create an empty model with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            components: HashMap::new(),
            boundaries: HashMap::new(),
            flows: HashMap::new(),
        }
    }

    /// Add a component to the model.
    pub fn add_component(&mut self, component: Component) -> Result<(), ThreatModelError> {
        if self.components.contains_key(&component.id) {
            return Err(ThreatModelError::DuplicateId(component.id));
        }
        self.components.insert(component.id.clone(), component);
        Ok(())
    }

    /// Add a trust boundary to the model.
    pub fn add_boundary(&mut self, boundary: Boundary) -> Result<(), ThreatModelError> {
        if self.boundaries.contains_key(&boundary.id) {
            return Err(ThreatModelError::DuplicateId(boundary.id));
        }
        self.boundaries.insert(boundary.id.clone(), boundary);
        Ok(())
    }

    /// Add a data flow to the model.
    pub fn add_data_flow(&mut self, flow: DataFlow) -> Result<(), ThreatModelError> {
        if self.flows.contains_key(&flow.id) {
            return Err(ThreatModelError::DuplicateId(flow.id.clone()));
        }
        if flow.source == flow.target {
            return Err(ThreatModelError::SelfReferentialFlow(flow.id));
        }
        self.flows.insert(flow.id.clone(), flow);
        Ok(())
    }

    /// Validate the model and return all STRIDE threats sorted by target and
    /// threat kind.
    pub fn analyze(&self) -> Result<Vec<Threat>, ThreatModelError> {
        self.validate()?;

        let exposed = self.exposed_components();
        let mut threats = Vec::new();

        let mut components: Vec<&Component> = self.components.values().collect();
        components.sort_by(|a, b| a.id.cmp(&b.id));
        for component in components {
            threats.extend(component_threats(component, exposed.contains(&component.id)));
        }

        let mut flows: Vec<&DataFlow> = self.flows.values().collect();
        flows.sort_by(|a, b| a.id.cmp(&b.id));
        for flow in flows {
            let crossing = self.flow_crosses_boundary(flow);
            let sensitive = flow_has_sensitive_data(flow);
            threats.extend(flow_threats(flow, crossing, sensitive));
        }

        threats.sort_by(|a, b| a.target.cmp(&b.target).then_with(|| a.kind.cmp(&b.kind)));

        Ok(threats)
    }

    fn validate(&self) -> Result<(), ThreatModelError> {
        for boundary in self.boundaries.values() {
            for component_id in &boundary.contains {
                if !self.components.contains_key(component_id) {
                    return Err(ThreatModelError::UnknownComponent {
                        reference: component_id.clone(),
                        context: format!("boundary {} contains", boundary.id),
                    });
                }
            }
            for component_id in &boundary.trusts {
                if !self.components.contains_key(component_id) {
                    return Err(ThreatModelError::UnknownComponent {
                        reference: component_id.clone(),
                        context: format!("boundary {} trusts", boundary.id),
                    });
                }
            }
        }

        for flow in self.flows.values() {
            if !self.components.contains_key(&flow.source) {
                return Err(ThreatModelError::UnknownComponent {
                    reference: flow.source.clone(),
                    context: format!("data flow {} source", flow.id),
                });
            }
            if !self.components.contains_key(&flow.target) {
                return Err(ThreatModelError::UnknownComponent {
                    reference: flow.target.clone(),
                    context: format!("data flow {} target", flow.id),
                });
            }
        }

        Ok(())
    }

    fn exposed_components(&self) -> HashSet<String> {
        let mut exposed = HashSet::new();
        for (id, component) in &self.components {
            if component.exposed {
                exposed.insert(id.clone());
            }
        }
        for boundary in self.boundaries.values() {
            if boundary.untrusted {
                for component_id in &boundary.contains {
                    exposed.insert(component_id.clone());
                }
                for component_id in &boundary.trusts {
                    exposed.insert(component_id.clone());
                }
            }
        }
        exposed
    }

    fn flow_crosses_boundary(&self, flow: &DataFlow) -> bool {
        for boundary in self.boundaries.values() {
            let src_contains = boundary.contains.contains(&flow.source);
            let dst_contains = boundary.contains.contains(&flow.target);
            let src_trusts = boundary.trusts.contains(&flow.source);
            let dst_trusts = boundary.trusts.contains(&flow.target);

            if (src_contains && dst_trusts) || (src_trusts && dst_contains) {
                return true;
            }
            if src_contains != dst_contains {
                return true;
            }
        }
        false
    }
}

const SENSITIVE_DATA_TYPES: &[&str] = &[
    "user-data",
    "pii",
    "payment-card",
    "credentials",
    "financial",
    "health",
    "password",
    "secret",
    "token",
];

const SECURE_PROTOCOLS: &[&str] = &["https", "tls", "mtls", "ssh"];

fn flow_has_sensitive_data(flow: &DataFlow) -> bool {
    flow.data_types
        .iter()
        .any(|d| SENSITIVE_DATA_TYPES.contains(&d.as_str()))
}

fn is_secure_protocol(protocol: &str) -> bool {
    SECURE_PROTOCOLS.contains(&protocol.to_lowercase().as_str())
}

fn component_threats(component: &Component, exposed: bool) -> Vec<Threat> {
    let mut threats = Vec::new();
    let has_data = !component.stores.is_empty() || !component.handles.is_empty();

    if exposed
        || component.component_type == "api"
        || component.component_type == "gateway"
        || component.component_type == "load-balancer"
    {
        threats.push(Threat::new(
            ThreatKind::Spoofing,
            &component.id,
            format!("{} may be spoofed by an attacker", component.name),
            vec![
                "Enforce strong authentication and caller identity verification".to_string(),
                "Use mutual TLS or service identity tokens".to_string(),
            ],
        ));
    }

    if has_data {
        threats.push(Threat::new(
            ThreatKind::Tampering,
            &component.id,
            format!(
                "{} processes or stores data that could be tampered with",
                component.name
            ),
            vec![
                "Validate and sanitize all inputs".to_string(),
                "Use integrity checks such as checksums or signatures".to_string(),
                "Restrict write access to authorized actors".to_string(),
            ],
        ));
    }

    if has_data {
        threats.push(Threat::new(
            ThreatKind::Repudiation,
            &component.id,
            format!("Actions on {} may not be provably logged", component.name),
            vec![
                "Implement immutable audit logging".to_string(),
                "Include non-repudiable timestamps and identities".to_string(),
                "Protect logs from tampering".to_string(),
            ],
        ));
    }

    if has_data {
        threats.push(Threat::new(
            ThreatKind::InformationDisclosure,
            &component.id,
            format!("{} may leak stored or processed data", component.name),
            vec![
                "Encrypt data at rest and in transit".to_string(),
                "Apply least-privilege and need-to-know access".to_string(),
                "Mask, tokenize, or redact sensitive fields".to_string(),
            ],
        ));
    }

    if exposed
        || component.component_type == "api"
        || component.component_type == "gateway"
        || component.component_type == "load-balancer"
    {
        threats.push(Threat::new(
            ThreatKind::DenialOfService,
            &component.id,
            format!(
                "{} may be targeted by a denial-of-service attack",
                component.name
            ),
            vec![
                "Implement rate limiting and throttling".to_string(),
                "Use DDoS protection, autoscaling, and load balancing".to_string(),
                "Apply resource quotas and circuit breakers".to_string(),
            ],
        ));
    }

    if component.environment == "k8s"
        || component.environment == "container"
        || component.environment == "vm"
        || component.component_type == "api"
        || component.component_type == "service"
    {
        threats.push(Threat::new(
            ThreatKind::ElevationOfPrivilege,
            &component.id,
            format!(
                "An attacker may gain unauthorized privileges on {}",
                component.name
            ),
            vec![
                "Apply least-privilege RBAC and service accounts".to_string(),
                "Use sandboxed or isolated execution environments".to_string(),
                "Regularly patch and harden host and container images".to_string(),
            ],
        ));
    }

    threats
}

fn flow_threats(flow: &DataFlow, crossing: bool, sensitive: bool) -> Vec<Threat> {
    let base = format!("Data flow {} from {} to {}", flow.id, flow.source, flow.target);
    let mut threats = Vec::new();

    let mut spoof_mits = vec![
        "Validate the source identity before processing".to_string(),
        "Use mutual TLS or signed tokens for callers".to_string(),
    ];
    if flow.auth.is_empty() {
        spoof_mits.insert(0, "Require authentication for this flow".to_string());
    }
    threats.push(Threat::new(
        ThreatKind::Spoofing,
        &flow.id,
        format!("{base} may be spoofed"),
        spoof_mits,
    ));

    let mut tamp_mits = vec![
        "Validate message integrity".to_string(),
        "Use signed or MAC-protected payloads".to_string(),
    ];
    if !is_secure_protocol(&flow.protocol) {
        tamp_mits.insert(0, "Encrypt the channel with TLS".to_string());
    }
    threats.push(Threat::new(
        ThreatKind::Tampering,
        &flow.id,
        format!("{base} may be tampered with in transit"),
        tamp_mits,
    ));

    threats.push(Threat::new(
        ThreatKind::Repudiation,
        &flow.id,
        format!("{base} may not leave a non-repudiable audit trail"),
        vec![
            "Log all requests with source and target identities".to_string(),
            "Protect logs from tampering".to_string(),
            "Include non-repudiable timestamps".to_string(),
        ],
    ));

    let mut info_mits = vec![
        "Minimize data shared over this flow".to_string(),
        "Apply field-level encryption or tokenization".to_string(),
    ];
    if !is_secure_protocol(&flow.protocol) {
        info_mits.insert(0, "Encrypt data in transit using TLS".to_string());
    }
    if sensitive {
        info_mits.insert(0, "Mask or tokenize sensitive data fields".to_string());
    }
    threats.push(Threat::new(
        ThreatKind::InformationDisclosure,
        &flow.id,
        format!("{base} may leak sensitive information"),
        info_mits,
    ));

    let mut dos_mits = vec![
        "Implement rate limiting and throttling".to_string(),
        "Use queues or load balancing to absorb spikes".to_string(),
        "Apply per-source quotas".to_string(),
    ];
    if !crossing {
        dos_mits.push("Validate internal callers to prevent resource abuse".to_string());
    }
    threats.push(Threat::new(
        ThreatKind::DenialOfService,
        &flow.id,
        format!("{base} may be used to deny service"),
        dos_mits,
    ));

    let mut ele_mits = vec![
        "Authorize every request".to_string(),
        "Validate caller privileges at the target".to_string(),
        "Use least-privilege access for the target".to_string(),
    ];
    if flow.auth.is_empty() {
        ele_mits.insert(0, "Enforce authentication before authorization".to_string());
    }
    threats.push(Threat::new(
        ThreatKind::ElevationOfPrivilege,
        &flow.id,
        format!("{base} may allow privilege escalation"),
        ele_mits,
    ));

    threats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_defaults() {
        let c = Component::new("api");
        assert_eq!(c.id, "api");
        assert_eq!(c.name, "api");
        assert_eq!(c.component_type, "service");
        assert!(c.stores.is_empty());
        assert!(c.handles.is_empty());
    }

    #[test]
    fn runs_in_alias() {
        let c = Component::new("api").runs_in("k8s");
        assert_eq!(c.environment, "k8s");
    }

    #[test]
    fn payment_api() {
        let mut app = Model::new("payment-api");
        app.add_component(
            Component::new("api")
                .name("Payment API")
                .component_type("api")
                .environment("k8s")
                .stores(&["user-data"])
                .exposed(true),
        )
        .unwrap();
        app.add_boundary(Boundary::new("internet").untrusted(true).trusts(&["api"]))
            .unwrap();

        let threats = app.analyze().unwrap();
        assert!(!threats.is_empty());

        let found: HashSet<_> = threats
            .iter()
            .filter(|t| t.target == "api")
            .map(|t| t.kind)
            .collect();
        for kind in [
            ThreatKind::Spoofing,
            ThreatKind::Tampering,
            ThreatKind::Repudiation,
            ThreatKind::InformationDisclosure,
            ThreatKind::DenialOfService,
            ThreatKind::ElevationOfPrivilege,
        ] {
            assert!(found.contains(&kind), "missing component threat {kind:?}");
        }
    }

    #[test]
    fn data_flow_threats() {
        let mut app = Model::new("web-shop");
        app.add_component(Component::new("browser").component_type("browser"))
            .unwrap();
        app.add_component(
            Component::new("api")
                .component_type("api")
                .environment("k8s")
                .exposed(true),
        )
        .unwrap();
        app.add_boundary(
            Boundary::new("internet")
                .untrusted(true)
                .contains(&["browser"])
                .trusts(&["api"]),
        )
        .unwrap();
        app.add_data_flow(
            DataFlow::new("login", "browser", "api")
                .protocol("https")
                .auth("bearer")
                .data_types(&["credentials"]),
        )
        .unwrap();

        let threats = app.analyze().unwrap();
        assert!(threats
            .iter()
            .any(|t| t.target == "login" && t.kind == ThreatKind::InformationDisclosure));
    }

    #[test]
    fn analyze_validation() {
        let mut app = Model::new("bad-boundary");
        app.add_component(Component::new("a")).unwrap();
        app.add_boundary(Boundary::new("b").contains(&["missing"]))
            .unwrap();
        assert!(app.analyze().is_err());

        let mut app2 = Model::new("bad-flow");
        app2.add_component(Component::new("a")).unwrap();
        app2.add_data_flow(DataFlow::new("f", "a", "missing")).unwrap();
        assert!(app2.analyze().is_err());

        let mut app3 = Model::new("dup");
        app3.add_component(Component::new("a")).unwrap();
        assert!(app3.add_component(Component::new("a")).is_err());
    }

    #[test]
    fn analyze_sorting() {
        let mut app = Model::new("sorted");
        app.add_component(Component::new("b")).unwrap();
        app.add_component(Component::new("a")).unwrap();
        let threats = app.analyze().unwrap();
        assert_eq!(threats.first().unwrap().target, "a");
    }

    #[test]
    fn threat_display() {
        let t = Threat::new(ThreatKind::Spoofing, "api", "desc", vec![]);
        assert_eq!(t.to_string(), "Spoofing on api");
    }
}
