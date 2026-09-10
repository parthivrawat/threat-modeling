package threatmodel

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestNewComponentDefaults(t *testing.T) {
	c := NewComponent("api", "API", nil)
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

	api := NewComponent("api", "Payment API", &ComponentOpts{
		Type:        "api",
		Environment: "k8s",
		Stores:      []string{"user-data"},
		Exposed:     true,
	})
	if err := m.AddComponent(api); err != nil {
		t.Fatalf("AddComponent: %v", err)
	}

	if err := m.AddBoundary(NewBoundary("internet", "Internet", &BoundaryOpts{
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

	if err := m.AddComponent(NewComponent("browser", "Browser", &ComponentOpts{Type: "browser"})); err != nil {
		t.Fatalf("AddComponent browser: %v", err)
	}
	if err := m.AddComponent(NewComponent("api", "API", &ComponentOpts{
		Type:        "api",
		Environment: "k8s",
		Exposed:     true,
	})); err != nil {
		t.Fatalf("AddComponent api: %v", err)
	}
	if err := m.AddBoundary(NewBoundary("internet", "Internet", &BoundaryOpts{
		Untrusted: true,
		Trusts:    []string{"api"},
	})); err != nil {
		t.Fatalf("AddBoundary: %v", err)
	}
	if err := m.AddDataFlow(NewDataFlow("login", "browser", "api", &FlowOpts{
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

	foundInfo, foundSpoof, foundTamp := false, false, false
	for _, th := range threats {
		if th.Target == "login" {
			switch th.Kind {
			case InformationDisclosure:
				foundInfo = true
			case Spoofing:
				foundSpoof = true
			case Tampering:
				foundTamp = true
			}
		}
	}
	if !foundInfo {
		t.Errorf("expected InformationDisclosure threat for login flow")
	}
	if !foundSpoof {
		t.Errorf("expected Spoofing threat for login flow")
	}
	if !foundTamp {
		t.Errorf("expected Tampering threat for login flow")
	}
}

func TestAnalyzeValidation(t *testing.T) {
	t.Run("unknown component in boundary", func(t *testing.T) {
		m := New("bad-boundary")
		if err := m.AddComponent(NewComponent("a", "A", nil)); err != nil {
			t.Fatalf("AddComponent: %v", err)
		}
		if err := m.AddBoundary(NewBoundary("b", "B", &BoundaryOpts{Contains: []string{"missing"}})); err == nil {
			t.Error("expected error for unknown component in boundary")
		}
	})

	t.Run("unknown flow target", func(t *testing.T) {
		m := New("bad-flow")
		if err := m.AddComponent(NewComponent("a", "A", nil)); err != nil {
			t.Fatalf("AddComponent: %v", err)
		}
		if err := m.AddDataFlow(NewDataFlow("f", "a", "missing", nil)); err == nil {
			t.Error("expected error for unknown flow target")
		}
	})

	t.Run("duplicate component", func(t *testing.T) {
		m := New("dup")
		c := NewComponent("a", "A", nil)
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
	if err := m.AddComponent(NewComponent("b", "B", &ComponentOpts{Stores: []string{"user-data"}})); err != nil {
		t.Fatalf("AddComponent: %v", err)
	}
	if err := m.AddComponent(NewComponent("a", "A", &ComponentOpts{Stores: []string{"user-data"}})); err != nil {
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

func TestDataFlowMitigated(t *testing.T) {
	m := New("web-shop")

	if err := m.AddComponent(NewComponent("browser", "Browser", &ComponentOpts{Type: "browser"})); err != nil {
		t.Fatalf("AddComponent browser: %v", err)
	}
	if err := m.AddComponent(NewComponent("api", "API", &ComponentOpts{
		Type:        "api",
		Environment: "k8s",
		Exposed:     true,
	})); err != nil {
		t.Fatalf("AddComponent api: %v", err)
	}
	if err := m.AddBoundary(NewBoundary("internet", "Internet", &BoundaryOpts{
		Untrusted: true,
		Trusts:    []string{"api"},
	})); err != nil {
		t.Fatalf("AddBoundary: %v", err)
	}
	if err := m.AddDataFlow(NewDataFlow("login", "browser", "api", &FlowOpts{
		Protocol: "https",
		Auth:     "bearer",
	})); err != nil {
		t.Fatalf("AddDataFlow: %v", err)
	}

	threats, err := m.Analyze()
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	found := map[ThreatKind]bool{}
	for _, th := range threats {
		if th.Target == "login" && (th.Kind == Spoofing || th.Kind == Tampering) {
			found[th.Kind] = true
			if th.Status != ThreatStatusMitigated {
				t.Errorf("expected %s on login to be Mitigated, got %s", th.Kind, th.Status)
			}
		}
	}
	if !found[Spoofing] {
		t.Errorf("expected Spoofing threat for login flow")
	}
	if !found[Tampering] {
		t.Errorf("expected Tampering threat for login flow")
	}
}

func TestFlowSensitiveDataCaseInsensitive(t *testing.T) {
	f := NewDataFlow("f", "a", "b", &FlowOpts{DataTypes: []string{"PII"}})
	if !FlowHasSensitiveData(f) {
		t.Error("expected FlowHasSensitiveData to detect PII case-insensitively")
	}
}

func TestFlowCrossesBoundaryNested(t *testing.T) {
	m := New("nested-boundary")

	if err := m.AddComponent(NewComponent("browser", "Browser", &ComponentOpts{Type: "browser"})); err != nil {
		t.Fatalf("AddComponent browser: %v", err)
	}
	if err := m.AddComponent(NewComponent("api", "API", &ComponentOpts{
		Type:        "api",
		Environment: "k8s",
	})); err != nil {
		t.Fatalf("AddComponent api: %v", err)
	}
	if err := m.AddComponent(NewComponent("db", "Database", &ComponentOpts{
		Type:        "database",
		Environment: "k8s",
		Stores:      []string{"user-data"},
	})); err != nil {
		t.Fatalf("AddComponent db: %v", err)
	}

	if err := m.AddBoundary(NewBoundary("internet", "Internet", &BoundaryOpts{
		Untrusted: true,
		Contains:  []string{"browser"},
		Trusts:    []string{"api"},
	})); err != nil {
		t.Fatalf("AddBoundary internet: %v", err)
	}
	if err := m.AddBoundary(NewBoundary("dmz", "DMZ", &BoundaryOpts{
		Contains: []string{"api"},
		Trusts:   []string{"db"},
	})); err != nil {
		t.Fatalf("AddBoundary dmz: %v", err)
	}

	if err := m.AddDataFlow(NewDataFlow("browser-api", "browser", "api", nil)); err != nil {
		t.Fatalf("AddDataFlow browser-api: %v", err)
	}
	if err := m.AddDataFlow(NewDataFlow("api-db", "api", "db", nil)); err != nil {
		t.Fatalf("AddDataFlow api-db: %v", err)
	}

	for _, id := range []string{"browser-api", "api-db"} {
		f, ok := m.flows[id]
		if !ok {
			t.Fatalf("missing flow %s", id)
		}
		if !m.flowCrossesBoundary(f) {
			t.Errorf("expected flow %s to cross boundary", id)
		}
	}
}

func TestComponentRunsInAlias(t *testing.T) {
	c := NewComponent("svc", "Service", &ComponentOpts{RunsIn: "k8s"})
	if c.Environment != "k8s" {
		t.Errorf("expected Environment set from RunsIn alias, got %q", c.Environment)
	}
}

func TestThreatDisplay(t *testing.T) {
	th := &Threat{Kind: Spoofing, Target: "api"}
	if got := th.String(); got != "Spoofing on api" {
		t.Errorf("expected %q, got %q", "Spoofing on api", got)
	}
}

func TestAnalyzeProperty(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	optsPool := []ComponentOpts{
		{Type: "api", Exposed: true},
		{Stores: []string{"user-data"}},
		{Handles: []string{"pii"}},
		{Type: "database", Stores: []string{"user-data"}},
	}
	for i := 0; i < 10; i++ {
		m := New(fmt.Sprintf("prop-%d", i))
		n := 2 + r.Intn(3)
		ids := make([]string, n)
		for j := 0; j < n; j++ {
			id := fmt.Sprintf("c%d", j)
			ids[j] = id
			opt := optsPool[r.Intn(len(optsPool))]
			if err := m.AddComponent(NewComponent(id, "", &opt)); err != nil {
				t.Fatalf("AddComponent %s: %v", id, err)
			}
		}
		if err := m.AddComponent(NewComponent(ids[0], "", nil)); err == nil {
			t.Errorf("iteration %d: expected error adding duplicate component", i)
		}
		if err := m.AddDataFlow(NewDataFlow(fmt.Sprintf("f%d", i), ids[0], ids[1], &FlowOpts{DataTypes: []string{"credentials"}})); err != nil {
			t.Fatalf("AddDataFlow: %v", err)
		}
		threats, err := m.Analyze()
		if err != nil {
			t.Fatalf("Analyze: %v", err)
		}
		if len(threats) == 0 {
			t.Fatalf("iteration %d: expected at least one threat", i)
		}
		for _, th := range threats {
			if th.Target == "" {
				t.Errorf("iteration %d: threat has empty Target", i)
			}
			if th.Kind == "" {
				t.Errorf("iteration %d: threat has empty Kind", i)
			}
		}
	}
}

func ExampleNew() {
	m := New("payment-api")
	fmt.Println(m.Name)
	// Output: payment-api
}
