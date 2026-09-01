package threatmodel

import (
	"fmt"
	"strings"
)

// ThreatKind is one of the six STRIDE categories.
type ThreatKind string

const (
	// Spoofing covers identity deception and impersonation.
	Spoofing ThreatKind = "Spoofing"
	// Tampering covers unauthorized modification of data or code.
	Tampering ThreatKind = "Tampering"
	// Repudiation covers inability to prove that an action occurred.
	Repudiation ThreatKind = "Repudiation"
	// InformationDisclosure covers unintended data exposure.
	InformationDisclosure ThreatKind = "InformationDisclosure"
	// DenialOfService covers availability attacks and resource exhaustion.
	DenialOfService ThreatKind = "DenialOfService"
	// ElevationOfPrivilege covers gaining unauthorized capabilities.
	ElevationOfPrivilege ThreatKind = "ElevationOfPrivilege"
)

// Threat represents a single identified threat and its recommended mitigations.
type Threat struct {
	Kind        ThreatKind
	Target      string
	Description string
	Mitigations []string
}

func (t Threat) String() string {
	return fmt.Sprintf("%s on %s", t.Kind, t.Target)
}

var sensitiveDataTypes = map[string]bool{
	"user-data":    true,
	"pii":          true,
	"payment-card": true,
	"credentials":  true,
	"financial":    true,
	"health":       true,
	"password":     true,
	"secret":       true,
	"token":        true,
}

func flowHasSensitiveData(f *DataFlow) bool {
	for _, d := range f.DataTypes {
		if sensitiveDataTypes[d] {
			return true
		}
	}
	return false
}

func isSecureProtocol(protocol string) bool {
	p := strings.ToLower(protocol)
	return p == "https" || p == "tls" || p == "mtls" || p == "ssh"
}

func appendComponentThreats(out []*Threat, c *Component, exposed bool) []*Threat {
	if exposed || c.Type == "api" || c.Type == "gateway" || c.Type == "load-balancer" {
		out = append(out, &Threat{
			Kind:        Spoofing,
			Target:      c.ID,
			Description: fmt.Sprintf("%s may be spoofed by an attacker", c.Name),
			Mitigations: []string{
				"Enforce strong authentication and caller identity verification",
				"Use mutual TLS or service identity tokens",
			},
		})
	}

	if len(c.Stores) > 0 || len(c.Handles) > 0 {
		out = append(out, &Threat{
			Kind:        Tampering,
			Target:      c.ID,
			Description: fmt.Sprintf("%s processes or stores data that could be tampered with", c.Name),
			Mitigations: []string{
				"Validate and sanitize all inputs",
				"Use integrity checks such as checksums or signatures",
				"Restrict write access to authorized actors",
			},
		})
	}

	if len(c.Handles) > 0 || len(c.Stores) > 0 {
		out = append(out, &Threat{
			Kind:        Repudiation,
			Target:      c.ID,
			Description: fmt.Sprintf("Actions on %s may not be provably logged", c.Name),
			Mitigations: []string{
				"Implement immutable audit logging",
				"Include non-repudiable timestamps and identities",
				"Protect logs from tampering",
			},
		})
	}

	if len(c.Stores) > 0 || len(c.Handles) > 0 {
		out = append(out, &Threat{
			Kind:        InformationDisclosure,
			Target:      c.ID,
			Description: fmt.Sprintf("%s may leak stored or processed data", c.Name),
			Mitigations: []string{
				"Encrypt data at rest and in transit",
				"Apply least-privilege and need-to-know access",
				"Mask, tokenize, or redact sensitive fields",
			},
		})
	}

	if exposed || c.Type == "api" || c.Type == "gateway" || c.Type == "load-balancer" {
		out = append(out, &Threat{
			Kind:        DenialOfService,
			Target:      c.ID,
			Description: fmt.Sprintf("%s may be targeted by a denial-of-service attack", c.Name),
			Mitigations: []string{
				"Implement rate limiting and throttling",
				"Use DDoS protection, autoscaling, and load balancing",
				"Apply resource quotas and circuit breakers",
			},
		})
	}

	if c.Environment == "k8s" || c.Environment == "container" || c.Environment == "vm" ||
		c.Type == "api" || c.Type == "service" {
		out = append(out, &Threat{
			Kind:        ElevationOfPrivilege,
			Target:      c.ID,
			Description: fmt.Sprintf("An attacker may gain unauthorized privileges on %s", c.Name),
			Mitigations: []string{
				"Apply least-privilege RBAC and service accounts",
				"Use sandboxed or isolated execution environments",
				"Regularly patch and harden host and container images",
			},
		})
	}

	return out
}

func appendFlowThreats(out []*Threat, f *DataFlow, crossing, sensitive bool) []*Threat {
	base := fmt.Sprintf("Data flow %s from %s to %s", f.ID, f.Source, f.Target)

	spoofMits := []string{
		"Validate the source identity before processing",
		"Use mutual TLS or signed tokens for callers",
	}
	if f.Auth == "" {
		spoofMits = append([]string{"Require authentication for this flow"}, spoofMits...)
	}
	out = append(out, &Threat{
		Kind:        Spoofing,
		Target:      f.ID,
		Description: base + " may be spoofed",
		Mitigations: spoofMits,
	})

	tampMits := []string{
		"Validate message integrity",
		"Use signed or MAC-protected payloads",
	}
	if !isSecureProtocol(f.Protocol) {
		tampMits = append([]string{"Encrypt the channel with TLS"}, tampMits...)
	}
	out = append(out, &Threat{
		Kind:        Tampering,
		Target:      f.ID,
		Description: base + " may be tampered with in transit",
		Mitigations: tampMits,
	})

	out = append(out, &Threat{
		Kind:        Repudiation,
		Target:      f.ID,
		Description: base + " may not leave a non-repudiable audit trail",
		Mitigations: []string{
			"Log all requests with source and target identities",
			"Protect logs from tampering",
			"Include non-repudiable timestamps",
		},
	})

	infoMits := []string{
		"Minimize data shared over this flow",
		"Apply field-level encryption or tokenization",
	}
	if !isSecureProtocol(f.Protocol) {
		infoMits = append([]string{"Encrypt data in transit using TLS"}, infoMits...)
	}
	if sensitive {
		infoMits = append([]string{"Mask or tokenize sensitive data fields"}, infoMits...)
	}
	out = append(out, &Threat{
		Kind:        InformationDisclosure,
		Target:      f.ID,
		Description: base + " may leak sensitive information",
		Mitigations: infoMits,
	})

	dosMits := []string{
		"Implement rate limiting and throttling",
		"Use queues or load balancing to absorb spikes",
		"Apply per-source quotas",
	}
	if !crossing {
		dosMits = append(dosMits, "Validate internal callers to prevent resource abuse")
	}
	out = append(out, &Threat{
		Kind:        DenialOfService,
		Target:      f.ID,
		Description: base + " may be used to deny service",
		Mitigations: dosMits,
	})

	eleMits := []string{
		"Authorize every request",
		"Validate caller privileges at the target",
		"Use least-privilege access for the target",
	}
	if f.Auth == "" {
		eleMits = append([]string{"Enforce authentication before authorization"}, eleMits...)
	}
	out = append(out, &Threat{
		Kind:        ElevationOfPrivilege,
		Target:      f.ID,
		Description: base + " may allow privilege escalation",
		Mitigations: eleMits,
	})

	return out
}
