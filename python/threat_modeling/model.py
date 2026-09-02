"""Core threat-modeling types and STRIDE analyzer."""

from __future__ import annotations

import enum
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Union


class ThreatKind(str, enum.Enum):
    """One of the six STRIDE threat categories."""

    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "InformationDisclosure"
    DENIAL_OF_SERVICE = "DenialOfService"
    ELEVATION_OF_PRIVILEGE = "ElevationOfPrivilege"

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True)
class Threat:
    """A single identified threat and its recommended mitigations."""

    kind: ThreatKind
    target: str
    description: str
    mitigations: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"{self.kind} on {self.target}"


SENSITIVE_DATA_TYPES: Set[str] = {
    "user-data",
    "pii",
    "payment-card",
    "credentials",
    "financial",
    "health",
    "password",
    "secret",
    "token",
}

SECURE_PROTOCOLS: Set[str] = {"https", "tls", "mtls", "ssh"}


class Component:
    """An architectural component such as an API, database, service, or browser."""

    def __init__(
        self,
        id: str,
        name: Optional[str] = None,
        *,
        component_type: str = "service",
        environment: Optional[str] = None,
        runs_in: Optional[str] = None,
        stores: Optional[List[str]] = None,
        handles: Optional[List[str]] = None,
        exposed: bool = False,
    ) -> None:
        self.id = id
        self.name = name or id
        self.component_type = component_type
        self.environment = environment or runs_in or ""
        self.stores = list(stores or [])
        self.handles = list(handles or [])
        self.exposed = exposed

    def __repr__(self) -> str:
        return f"Component({self.id!r}, name={self.name!r})"


class Boundary:
    """A trust boundary separating components."""

    def __init__(
        self,
        id: str,
        name: Optional[str] = None,
        *,
        untrusted: bool = False,
        contains: Optional[List[str]] = None,
        trusts: Optional[List[str]] = None,
    ) -> None:
        self.id = id
        self.name = name or id
        self.untrusted = untrusted
        self.contains = list(contains or [])
        self.trusts = list(trusts or [])

    def __repr__(self) -> str:
        return f"Boundary({self.id!r}, name={self.name!r})"


class DataFlow:
    """A data flow from a source component to a target component."""

    def __init__(
        self,
        id: str,
        source: str,
        target: str,
        *,
        protocol: str = "",
        auth: str = "",
        data_types: Optional[List[str]] = None,
    ) -> None:
        self.id = id
        self.source = source
        self.target = target
        self.protocol = protocol
        self.auth = auth
        self.data_types = list(data_types or [])

    def __repr__(self) -> str:
        return f"DataFlow({self.id!r}, {self.source!r} -> {self.target!r})"


Item = Union[Component, Boundary, DataFlow]


class Model:
    """A threat model made up of components, boundaries, and data flows."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._components: Dict[str, Component] = {}
        self._boundaries: Dict[str, Boundary] = {}
        self._flows: Dict[str, DataFlow] = {}
        self._lock = threading.RLock()

    def add(self, item: Item) -> None:
        """Add a Component, Boundary, or DataFlow to the model."""
        if isinstance(item, Component):
            self.add_component(item)
        elif isinstance(item, Boundary):
            self.add_boundary(item)
        elif isinstance(item, DataFlow):
            self.add_data_flow(item)
        else:
            raise TypeError(f"unsupported item type: {type(item)!r}")

    def add_component(self, component: Component) -> None:
        """Add a component to the model."""
        with self._lock:
            if component.id in self._components:
                raise ValueError(f"component ID already exists: {component.id}")
            self._components[component.id] = component

    def add_boundary(self, boundary: Boundary) -> None:
        """Add a trust boundary to the model."""
        with self._lock:
            if boundary.id in self._boundaries:
                raise ValueError(f"boundary ID already exists: {boundary.id}")
            self._boundaries[boundary.id] = boundary

    def add_data_flow(self, flow: DataFlow) -> None:
        """Add a data flow to the model."""
        with self._lock:
            if flow.id in self._flows:
                raise ValueError(f"data flow ID already exists: {flow.id}")
            if flow.source == flow.target:
                raise ValueError(f"data flow {flow.id} is self-referential")
            self._flows[flow.id] = flow

    def analyze(self) -> List[Threat]:
        """Validate the model and return all STRIDE threats."""
        with self._lock:
            self._validate()
            exposed = self._exposed_components()
            threats: List[Threat] = []

            for cid in sorted(self._components):
                component = self._components[cid]
                threats.extend(_component_threats(component, exposed.get(cid, False)))

            for fid in sorted(self._flows):
                flow = self._flows[fid]
                crossing = self._flow_crosses_boundary(flow)
                sensitive = _flow_has_sensitive_data(flow)
                threats.extend(_flow_threats(flow, crossing, sensitive))

            threats.sort(key=lambda t: (t.target, str(t.kind)))
            return threats

    def _validate(self) -> None:
        for boundary in self._boundaries.values():
            for component_id in boundary.contains:
                if component_id not in self._components:
                    raise ValueError(
                        f"boundary {boundary.id!r} contains unknown component {component_id!r}"
                    )
            for component_id in boundary.trusts:
                if component_id not in self._components:
                    raise ValueError(
                        f"boundary {boundary.id!r} trusts unknown component {component_id!r}"
                    )

        for flow in self._flows.values():
            if flow.source not in self._components:
                raise ValueError(f"data flow {flow.id!r} has unknown source {flow.source!r}")
            if flow.target not in self._components:
                raise ValueError(f"data flow {flow.id!r} has unknown target {flow.target!r}")

    def _exposed_components(self) -> Dict[str, bool]:
        exposed: Dict[str, bool] = {}
        for component_id, component in self._components.items():
            if component.exposed:
                exposed[component_id] = True
        for boundary in self._boundaries.values():
            if boundary.untrusted:
                for component_id in boundary.contains:
                    exposed[component_id] = True
                for component_id in boundary.trusts:
                    exposed[component_id] = True
        return exposed

    def _flow_crosses_boundary(self, flow: DataFlow) -> bool:
        for boundary in self._boundaries.values():
            src_contains = flow.source in boundary.contains
            dst_contains = flow.target in boundary.contains
            src_trusts = flow.source in boundary.trusts
            dst_trusts = flow.target in boundary.trusts

            if (src_contains and dst_trusts) or (src_trusts and dst_contains):
                return True
            if src_contains != dst_contains:
                return True
        return False


def _flow_has_sensitive_data(flow: DataFlow) -> bool:
    return any(dtype in SENSITIVE_DATA_TYPES for dtype in flow.data_types)


def _is_secure_protocol(protocol: str) -> bool:
    return protocol.lower() in SECURE_PROTOCOLS


def _component_threats(component: Component, exposed: bool) -> List[Threat]:
    threats: List[Threat] = []
    has_data = bool(component.stores or component.handles)

    if exposed or component.component_type in {"api", "gateway", "load-balancer"}:
        threats.append(
            Threat(
                kind=ThreatKind.SPOOFING,
                target=component.id,
                description=f"{component.name} may be spoofed by an attacker",
                mitigations=[
                    "Enforce strong authentication and caller identity verification",
                    "Use mutual TLS or service identity tokens",
                ],
            )
        )

    if has_data:
        threats.append(
            Threat(
                kind=ThreatKind.TAMPERING,
                target=component.id,
                description=f"{component.name} processes or stores data that could be tampered with",
                mitigations=[
                    "Validate and sanitize all inputs",
                    "Use integrity checks such as checksums or signatures",
                    "Restrict write access to authorized actors",
                ],
            )
        )

    if has_data:
        threats.append(
            Threat(
                kind=ThreatKind.REPUDIATION,
                target=component.id,
                description=f"Actions on {component.name} may not be provably logged",
                mitigations=[
                    "Implement immutable audit logging",
                    "Include non-repudiable timestamps and identities",
                    "Protect logs from tampering",
                ],
            )
        )

    if has_data:
        threats.append(
            Threat(
                kind=ThreatKind.INFORMATION_DISCLOSURE,
                target=component.id,
                description=f"{component.name} may leak stored or processed data",
                mitigations=[
                    "Encrypt data at rest and in transit",
                    "Apply least-privilege and need-to-know access",
                    "Mask, tokenize, or redact sensitive fields",
                ],
            )
        )

    if exposed or component.component_type in {"api", "gateway", "load-balancer"}:
        threats.append(
            Threat(
                kind=ThreatKind.DENIAL_OF_SERVICE,
                target=component.id,
                description=f"{component.name} may be targeted by a denial-of-service attack",
                mitigations=[
                    "Implement rate limiting and throttling",
                    "Use DDoS protection, autoscaling, and load balancing",
                    "Apply resource quotas and circuit breakers",
                ],
            )
        )

    if (
        component.environment in {"k8s", "container", "vm"}
        or component.component_type in {"api", "service"}
    ):
        threats.append(
            Threat(
                kind=ThreatKind.ELEVATION_OF_PRIVILEGE,
                target=component.id,
                description=f"An attacker may gain unauthorized privileges on {component.name}",
                mitigations=[
                    "Apply least-privilege RBAC and service accounts",
                    "Use sandboxed or isolated execution environments",
                    "Regularly patch and harden host and container images",
                ],
            )
        )

    return threats


def _flow_threats(flow: DataFlow, crossing: bool, sensitive: bool) -> List[Threat]:
    base = f"Data flow {flow.id} from {flow.source} to {flow.target}"
    threats: List[Threat] = []

    spoof_mitigations = [
        "Validate the source identity before processing",
        "Use mutual TLS or signed tokens for callers",
    ]
    if not flow.auth:
        spoof_mitigations.insert(0, "Require authentication for this flow")
    threats.append(
        Threat(
            kind=ThreatKind.SPOOFING,
            target=flow.id,
            description=f"{base} may be spoofed",
            mitigations=spoof_mitigations,
        )
    )

    tamper_mitigations = [
        "Validate message integrity",
        "Use signed or MAC-protected payloads",
    ]
    if not _is_secure_protocol(flow.protocol):
        tamper_mitigations.insert(0, "Encrypt the channel with TLS")
    threats.append(
        Threat(
            kind=ThreatKind.TAMPERING,
            target=flow.id,
            description=f"{base} may be tampered with in transit",
            mitigations=tamper_mitigations,
        )
    )

    threats.append(
        Threat(
            kind=ThreatKind.REPUDIATION,
            target=flow.id,
            description=f"{base} may not leave a non-repudiable audit trail",
            mitigations=[
                "Log all requests with source and target identities",
                "Protect logs from tampering",
                "Include non-repudiable timestamps",
            ],
        )
    )

    info_mitigations = [
        "Minimize data shared over this flow",
        "Apply field-level encryption or tokenization",
    ]
    if not _is_secure_protocol(flow.protocol):
        info_mitigations.insert(0, "Encrypt data in transit using TLS")
    if sensitive:
        info_mitigations.insert(0, "Mask or tokenize sensitive data fields")
    threats.append(
        Threat(
            kind=ThreatKind.INFORMATION_DISCLOSURE,
            target=flow.id,
            description=f"{base} may leak sensitive information",
            mitigations=info_mitigations,
        )
    )

    dos_mitigations = [
        "Implement rate limiting and throttling",
        "Use queues or load balancing to absorb spikes",
        "Apply per-source quotas",
    ]
    if not crossing:
        dos_mitigations.append("Validate internal callers to prevent resource abuse")
    threats.append(
        Threat(
            kind=ThreatKind.DENIAL_OF_SERVICE,
            target=flow.id,
            description=f"{base} may be used to deny service",
            mitigations=dos_mitigations,
        )
    )

    elevation_mitigations = [
        "Authorize every request",
        "Validate caller privileges at the target",
        "Use least-privilege access for the target",
    ]
    if not flow.auth:
        elevation_mitigations.insert(0, "Enforce authentication before authorization")
    threats.append(
        Threat(
            kind=ThreatKind.ELEVATION_OF_PRIVILEGE,
            target=flow.id,
            description=f"{base} may allow privilege escalation",
            mitigations=elevation_mitigations,
        )
    )

    return threats
