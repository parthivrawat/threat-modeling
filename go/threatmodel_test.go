package threatmodel

import (
	"fmt"
	"testing"
)

func TestNewComponentDefaults(t *testing.T) {
	c := NewComponent("api", "API")
	if c.ID != "api" {
		t.Errorf("expected ID api, got %s", c.ID)
	}
	if c.Name != "API" {
		t.Errorf("expected name API, got %s", c.Name)
	}
	if c.Type != "service" {
		t.Errorf("expected default type service, got %s", c.Type)
	}
}

func TestPaymentAPI(t *testing.T) {
	m := New("payment-api")

	api := NewComponent("api", "Payment API", ComponentOpts{
		Type:        "api",
		Environment: "k8s",
		Stores:      []string{"user-data"},
		Exposed:     true,
	})
	if err := m.AddComponent(api); err != nil {
		t.Fatalf("AddComponent: %v", err)
	}

	if err := m.AddBoundary(NewBoundary("internet", "Internet", BoundaryOpts{
		Untrusted: true,
		Trusts:    []string{"api"},
	})); err != nil {
		t.Fatalf("AddBoundary: %v", err)
	}

	threats, err := m.Analyze()
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(threats) == 0 {
		t.Fatal("expected at least one threat")
	}

	found := map[ThreatKind]bool{}
	for _, th := range threats {
		if th.Target == "api" {
			found[th.Kind] = true
		}
	}

	for _, kind := range []ThreatKind{Spoofing, Tampering, Repudiation, InformationDisclosure, DenialOfService, ElevationOfPrivilege} {
		if !found[kind] {
			t.Errorf("missing expected component threat %s for api", kind)
		}
	}
}

func TestDataFlowThreats(t *testing.T) {
	m := New("web-shop")

	if err := m.AddComponent(NewComponent("browser", "Browser", ComponentOpts{Type: "browser"})); err != nil {
		t.Fatalf("AddComponent browser: %v", err)
	}
	if err := m.AddComponent(NewComponent("api", "API", ComponentOpts{
		Type:        "api",
		Environment: "k8s",
		Exposed:     true,
	})); err != nil {
		t.Fatalf("AddComponent api: %v", err)
	}
	if err := m.AddBoundary(NewBoundary("internet", "Internet", BoundaryOpts{
		Untrusted: true,
		Trusts:    []string{"api"},
	})); err != nil {
		t.Fatalf("AddBoundary: %v", err)
	}
	if err := m.AddDataFlow(NewDataFlow("login", "browser", "api", FlowOpts{
		Protocol:  "https",
		Auth:      "bearer",
		DataTypes: []string{"credentials"},
	})); err != nil {
		t.Fatalf("AddDataFlow: %v", err)
	}

	threats, err := m.Analyze()
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	foundInfo := false
	for _, th := range threats {
		if th.Target == "login" && th.Kind == InformationDisclosure {
			foundInfo = true
		}
	}
	if !foundInfo {
		t.Errorf("expected InformationDisclosure threat for login flow")
	}
}

func TestAnalyzeValidation(t *testing.T) {
	t.Run("unknown component in boundary", func(t *testing.T) {
		m := New("bad-boundary")
		if err := m.AddComponent(NewComponent("a", "A")); err != nil {
			t.Fatalf("AddComponent: %v", err)
		}
		if err := m.AddBoundary(NewBoundary("b", "B", BoundaryOpts{Contains: []string{"missing"}})); err != nil {
			t.Fatalf("AddBoundary: %v", err)
		}
		if _, err := m.Analyze(); err == nil {
			t.Error("expected error for unknown component in boundary")
		}
	})

	t.Run("unknown flow target", func(t *testing.T) {
		m := New("bad-flow")
		if err := m.AddComponent(NewComponent("a", "A")); err != nil {
			t.Fatalf("AddComponent: %v", err)
		}
		if err := m.AddDataFlow(NewDataFlow("f", "a", "missing")); err != nil {
			t.Fatalf("AddDataFlow: %v", err)
		}
		if _, err := m.Analyze(); err == nil {
			t.Error("expected error for unknown flow target")
		}
	})

	t.Run("duplicate component", func(t *testing.T) {
		m := New("dup")
		c := NewComponent("a", "A")
		if err := m.AddComponent(c); err != nil {
			t.Fatalf("AddComponent: %v", err)
		}
		if err := m.AddComponent(c); err == nil {
			t.Error("expected error for duplicate component ID")
		}
	})
}

func TestModelAnalyzeSorting(t *testing.T) {
	m := New("sorted")
	if err := m.AddComponent(NewComponent("b", "B")); err != nil {
		t.Fatalf("AddComponent: %v", err)
	}
	if err := m.AddComponent(NewComponent("a", "A")); err != nil {
		t.Fatalf("AddComponent: %v", err)
	}

	threats, err := m.Analyze()
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(threats) == 0 {
		t.Fatal("expected threats")
	}
	if threats[0].Target != "a" {
		t.Errorf("expected first threat target a, got %s", threats[0].Target)
	}
}

func ExampleNew() {
	m := New("payment-api")
	fmt.Println(m.Name)
	// Output: payment-api
}
