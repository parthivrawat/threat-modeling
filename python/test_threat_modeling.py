"""Tests for the threat_modeling package."""

import random

import pytest

from threat_modeling import (
    Boundary,
    Component,
    DataFlow,
    Model,
    Severity,
    Threat,
    ThreatKind,
    ThreatStatus,
)


def test_component_defaults():
    c = Component("api")
    assert c.id == "api"
    assert c.name == "api"
    assert c.component_type == "service"
    assert c.stores == []
    assert c.handles == []


def test_component_runs_in_alias():
    c = Component("api", runs_in="k8s")
    assert c.environment == "k8s"


def test_payment_api():
    app = Model("payment-api")
    app.add(
        Component(
            "api",
            name="Payment API",
            component_type="api",
            environment="k8s",
            stores=["user-data"],
            exposed=True,
        )
    )
    app.add(Boundary("internet", untrusted=True, trusts=["api"]))

    threats = app.analyze()
    assert threats

    found = {th.kind for th in threats if th.target == "api"}
    for kind in ThreatKind:
        assert kind in found, f"missing component threat {kind} for api"


def test_data_flow_threats():
    app = Model("web-shop")
    app.add(Component("browser", component_type="browser"))
    app.add(
        Component(
            "api",
            component_type="api",
            environment="k8s",
            exposed=True,
        )
    )
    app.add(
        Boundary(
            "internet",
            untrusted=True,
            contains=["browser"],
            trusts=["api"],
        )
    )
    app.add(
        DataFlow(
            "login",
            "browser",
            "api",
            protocol="https",
            auth="bearer",
            data_types=["credentials"],
        )
    )

    threats = app.analyze()
    assert any(
        th.target == "login" and th.kind == ThreatKind.INFORMATION_DISCLOSURE
        for th in threats
    )


def test_flow_mitigated_status():
    app = Model("mitigated-flow")
    app.add(Component("browser", component_type="browser"))
    app.add(Component("api", component_type="api", exposed=True))
    app.add(
        Boundary(
            "internet",
            untrusted=True,
            contains=["browser"],
            trusts=["api"],
        )
    )
    app.add(
        DataFlow(
            "login",
            "browser",
            "api",
            protocol="https",
            auth="bearer",
            data_types=["credentials"],
        )
    )

    threats = {th.kind: th for th in app.analyze() if th.target == "login"}
    assert threats[ThreatKind.SPOOFING].status == ThreatStatus.MITIGATED
    assert threats[ThreatKind.TAMPERING].status == ThreatStatus.MITIGATED
    assert threats[ThreatKind.INFORMATION_DISCLOSURE].status == ThreatStatus.OPEN
    assert threats[ThreatKind.ELEVATION_OF_PRIVILEGE].status == ThreatStatus.MITIGATED
    assert threats[ThreatKind.REPUDIATION].status == ThreatStatus.OPEN
    assert threats[ThreatKind.DENIAL_OF_SERVICE].status == ThreatStatus.OPEN


def test_analyze_validation():
    app = Model("bad-boundary")
    app.add(Component("a"))
    with pytest.raises(ValueError):
        app.add(Boundary("b", contains=["missing"]))

    app2 = Model("bad-flow")
    app2.add(Component("a"))
    with pytest.raises(ValueError):
        app2.add(DataFlow("f", "a", "missing"))

    app3 = Model("dup")
    c = Component("a")
    app3.add(c)
    with pytest.raises(ValueError):
        app3.add(c)


def test_analyze_sorting():
    app = Model("sorted")
    app.add(Component("b", stores=["user-data"]))
    app.add(Component("a", stores=["user-data"]))
    threats = app.analyze()
    assert threats[0].target == "a"


def test_flow_crosses_boundary_nested():
    app = Model("nested-boundaries")
    app.add(Component("browser", component_type="browser"))
    app.add(Component("api", component_type="api"))
    app.add(Component("db", component_type="database"))
    app.add(
        Boundary(
            "internet",
            untrusted=True,
            contains=["browser"],
            trusts=["api"],
        )
    )
    app.add(
        Boundary(
            "dmz",
            contains=["api"],
            trusts=["db"],
        )
    )
    app.add(DataFlow("b2a", "browser", "api"))
    app.add(DataFlow("a2d", "api", "db"))

    for flow in app._flows.values():
        assert app._flow_crosses_boundary(flow) is True


def test_flow_sensitive_data_case_insensitive():
    app = Model("case-insensitive")
    app.add(Component("browser", component_type="browser"))
    app.add(Component("api", component_type="api", exposed=True))
    app.add(
        Boundary(
            "internet",
            untrusted=True,
            contains=["browser"],
            trusts=["api"],
        )
    )
    app.add(
        DataFlow(
            "login",
            "browser",
            "api",
            protocol="https",
            auth="bearer",
            data_types=["PII"],
        )
    )

    threats = app.analyze()
    info = next(
        th
        for th in threats
        if th.target == "login" and th.kind == ThreatKind.INFORMATION_DISCLOSURE
    )
    assert "Mask or tokenize sensitive data fields" in info.mitigations


def test_threat_display():
    threat = Threat(
        ThreatKind.SPOOFING,
        "api",
        "desc",
        [],
        ThreatStatus.OPEN,
        Severity.LOW,
    )
    assert str(threat) == "Spoofing on api"


def test_analyze_property():
    random.seed(0)
    n = random.randint(5, 10)
    for i in range(n):
        app = Model(f"prop-{i}")
        app.add(Component(f"api-{i}", component_type="api", exposed=True))
        app.add(Component(f"db-{i}", stores=["user-data"]))
        if random.random() < 0.8:
            app.add(
                DataFlow(
                    f"flow-{i}",
                    f"api-{i}",
                    f"db-{i}",
                    data_types=["user-data"],
                )
            )
        threats = app.analyze()
        assert threats
        for th in threats:
            assert th.target
            assert th.kind in ThreatKind

    invalid = Model("invalid-flow")
    invalid.add(Component("only"))
    with pytest.raises(ValueError):
        invalid.add(DataFlow("bad", "only", "missing-target"))
