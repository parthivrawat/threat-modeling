package threatmodel

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Component represents an architectural component such as an API, database,
// service, or browser.
type Component struct {
	ID          string
	Name        string
	Type        string
	Environment string
	Stores      []string
	Handles     []string
	Exposed     bool
}

// ComponentOpts configures a newly created Component.
type ComponentOpts struct {
	Type        string
	Environment string
	Stores      []string
	Handles     []string
	Exposed     bool
}

// NewComponent creates a Component with the provided identifier and options.
func NewComponent(id, name string, opts ...ComponentOpts) *Component {
	c := &Component{
		ID:   id,
		Name: name,
		Type: "service",
	}
	if c.Name == "" {
		c.Name = c.ID
	}
	if len(opts) > 0 {
		o := opts[0]
		if o.Type != "" {
			c.Type = o.Type
		}
		if o.Environment != "" {
			c.Environment = o.Environment
		}
		c.Stores = append([]string(nil), o.Stores...)
		c.Handles = append([]string(nil), o.Handles...)
		c.Exposed = o.Exposed
	}
	return c
}

// Boundary represents a trust boundary. Components listed in Contains are
// considered to be inside the boundary; components in Trusts are explicitly
// trusted by the boundary. An Untrusted boundary is treated as an external,
// potentially hostile zone such as the public internet.
type Boundary struct {
	ID        string
	Name      string
	Untrusted bool
	Contains  []string
	Trusts    []string
}

// BoundaryOpts configures a newly created Boundary.
type BoundaryOpts struct {
	Untrusted bool
	Contains  []string
	Trusts    []string
}

// NewBoundary creates a Boundary with the provided identifier and options.
func NewBoundary(id, name string, opts ...BoundaryOpts) *Boundary {
	b := &Boundary{
		ID:   id,
		Name: name,
	}
	if b.Name == "" {
		b.Name = b.ID
	}
	if len(opts) > 0 {
		o := opts[0]
		b.Untrusted = o.Untrusted
		b.Contains = append([]string(nil), o.Contains...)
		b.Trusts = append([]string(nil), o.Trusts...)
	}
	return b
}

// DataFlow represents an interaction between two components.
type DataFlow struct {
	ID        string
	Source    string
	Target    string
	Protocol  string
	Auth      string
	DataTypes []string
}

// FlowOpts configures a newly created DataFlow.
type FlowOpts struct {
	Protocol  string
	Auth      string
	DataTypes []string
}

// NewDataFlow creates a DataFlow from source to target with the given options.
func NewDataFlow(id, source, target string, opts ...FlowOpts) *DataFlow {
	f := &DataFlow{
		ID:     id,
		Source: source,
		Target: target,
	}
	if len(opts) > 0 {
		o := opts[0]
		f.Protocol = o.Protocol
		f.Auth = o.Auth
		f.DataTypes = append([]string(nil), o.DataTypes...)
	}
	return f
}

// Model holds a threat model made up of components, trust boundaries, and data
// flows. It is safe for concurrent use.
type Model struct {
	Name       string
	components map[string]*Component
	boundaries map[string]*Boundary
	flows      map[string]*DataFlow
	mu         sync.RWMutex
}

// New creates an empty Model with the given name.
func New(name string) *Model {
	return &Model{
		Name:       name,
		components: make(map[string]*Component),
		boundaries: make(map[string]*Boundary),
		flows:      make(map[string]*DataFlow),
	}
}

// AddComponent adds a component to the model. It returns an error if the
// component is nil, has an empty ID, or duplicates an existing ID.
func (m *Model) AddComponent(c *Component) error {
	if c == nil {
		return errors.New("cannot add nil component")
	}
	if c.ID == "" {
		return errors.New("component ID is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.components[c.ID]; exists {
		return fmt.Errorf("component ID already exists: %s", c.ID)
	}
	m.components[c.ID] = c
	return nil
}

// AddBoundary adds a trust boundary to the model.
func (m *Model) AddBoundary(b *Boundary) error {
	if b == nil {
		return errors.New("cannot add nil boundary")
	}
	if b.ID == "" {
		return errors.New("boundary ID is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.boundaries[b.ID]; exists {
		return fmt.Errorf("boundary ID already exists: %s", b.ID)
	}
	m.boundaries[b.ID] = b
	return nil
}

// AddDataFlow adds a data flow to the model.
func (m *Model) AddDataFlow(f *DataFlow) error {
	if f == nil {
		return errors.New("cannot add nil data flow")
	}
	if f.ID == "" {
		return errors.New("data flow ID is required")
	}
	if f.Source == "" || f.Target == "" {
		return errors.New("data flow source and target are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.flows[f.ID]; exists {
		return fmt.Errorf("data flow ID already exists: %s", f.ID)
	}
	m.flows[f.ID] = f
	return nil
}

// Analyze validates the model and returns all STRIDE threats with their
// mitigations. Threats are sorted by target and then by threat kind.
func (m *Model) Analyze() ([]*Threat, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if err := m.validate(); err != nil {
		return nil, err
	}

	exposed := m.exposedComponents()
	var threats []*Threat

	compIDs := sortedKeys(m.components)
	for _, id := range compIDs {
		threats = appendComponentThreats(threats, m.components[id], exposed[id])
	}

	flowIDs := sortedKeys(m.flows)
	for _, id := range flowIDs {
		f := m.flows[id]
		crossing := m.flowCrossesBoundary(f)
		sensitive := flowHasSensitiveData(f)
		threats = appendFlowThreats(threats, f, crossing, sensitive)
	}

	sort.Slice(threats, func(i, j int) bool {
		if threats[i].Target == threats[j].Target {
			return threats[i].Kind < threats[j].Kind
		}
		return threats[i].Target < threats[j].Target
	})

	return threats, nil
}

func (m *Model) validate() error {
	for _, b := range m.boundaries {
		for _, id := range b.Contains {
			if _, ok := m.components[id]; !ok {
				return fmt.Errorf("boundary %q contains unknown component %q", b.ID, id)
			}
		}
		for _, id := range b.Trusts {
			if _, ok := m.components[id]; !ok {
				return fmt.Errorf("boundary %q trusts unknown component %q", b.ID, id)
			}
		}
	}

	for _, f := range m.flows {
		if _, ok := m.components[f.Source]; !ok {
			return fmt.Errorf("data flow %q has unknown source %q", f.ID, f.Source)
		}
		if _, ok := m.components[f.Target]; !ok {
			return fmt.Errorf("data flow %q has unknown target %q", f.ID, f.Target)
		}
		if f.Source == f.Target {
			return fmt.Errorf("data flow %q is self-referential", f.ID)
		}
	}

	return nil
}

func (m *Model) exposedComponents() map[string]bool {
	exposed := make(map[string]bool)
	for id, c := range m.components {
		if c.Exposed {
			exposed[id] = true
		}
	}
	for _, b := range m.boundaries {
		if b.Untrusted {
			for _, id := range b.Contains {
				exposed[id] = true
			}
			for _, id := range b.Trusts {
				exposed[id] = true
			}
		}
	}
	return exposed
}

func (m *Model) flowCrossesBoundary(f *DataFlow) bool {
	for _, b := range m.boundaries {
		srcContains := contains(b.Contains, f.Source)
		dstContains := contains(b.Contains, f.Target)
		srcTrusts := contains(b.Trusts, f.Source)
		dstTrusts := contains(b.Trusts, f.Target)

		if (srcContains && dstTrusts) || (srcTrusts && dstContains) {
			return true
		}
		if srcContains != dstContains {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}
