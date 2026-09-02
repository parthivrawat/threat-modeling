"""Tests for the threat_modeling package."""

import pytest

from threat_modeling import Boundary, Component, DataFlow, Model, ThreatKind


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


def test_analyze_validation():
    app = Model("bad-boundary")
    app.add(Component("a"))
    app.add(Boundary("b", contains=["missing"]))
    with pytest.raises(ValueError):
        app.analyze()

    app2 = Model("bad-flow")
    app2.add(Component("a"))
    app2.add(DataFlow("f", "a", "missing"))
    with pytest.raises(ValueError):
        app2.analyze()

    app3 = Model("dup")
    c = Component("a")
    app3.add(c)
    with pytest.raises(ValueError):
        app3.add(c)


def test_analyze_sorting():
    app = Model("sorted")
    app.add(Component("b"))
    app.add(Component("a"))
    threats = app.analyze()
    assert threats[0].target == "a"
