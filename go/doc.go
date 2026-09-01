// Package threatmodel provides a declarative threat-modeling language and
// analyzer for Go applications. Teams can express systems as components, trust
// boundaries, and data flows, then apply the STRIDE methodology to generate
// targeted, actionable mitigations directly from code.
//
// # Quick Start
//
//	import "github.com/parthivrawat/threat-modeling/go"
//
//	m := threatmodel.New("payment-api")
//
//	c := threatmodel.NewComponent("api", "Payment API", threatmodel.ComponentOpts{
//	    Type:        "api",
//	    Environment: "k8s",
//	    Stores:      []string{"user-data"},
//	    Exposed:     true,
//	})
//	if err := m.AddComponent(c); err != nil {
//	    log.Fatal(err)
//	}
//
//	b := threatmodel.NewBoundary("internet", "Internet", threatmodel.BoundaryOpts{
//	    Untrusted: true,
//	    Trusts:    []string{"api"},
//	})
//	if err := m.AddBoundary(b); err != nil {
//	    log.Fatal(err)
//	}
//
//	threats, err := m.Analyze()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, t := range threats {
//	    fmt.Println(t.Kind, "-", t.Target)
//	    for _, mitigation := range t.Mitigations {
//	        fmt.Println("  -", mitigation)
//	    }
//	}
//
// # Features
//
//   - Declarative model, component, trust boundary, and data flow types
//   - STRIDE threat classification with built-in mitigation catalog
//   - Trust-boundary-aware analysis for data flows
//   - Goroutine-safe model construction and analysis
//   - Zero runtime dependencies
//
// # Thread Safety
//
// A Model may be used concurrently. AddComponent, AddBoundary, AddDataFlow, and
// Analyze all synchronize internal state with a read/write mutex.
//
// # Documentation
//
// For complete documentation, visit:
// https://pkg.go.dev/github.com/parthivrawat/threat-modeling/go
//
// # Source Code
//
// https://github.com/parthivrawat/threat-modeling
package threatmodel
