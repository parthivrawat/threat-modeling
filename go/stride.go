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

// ThreatStatus represents whether a threat is open or has been mitigated.
type ThreatStatus string

const (
	// ThreatStatusOpen means the threat has not been addressed.
	ThreatStatusOpen ThreatStatus = "Open"
	// ThreatStatusMitigated means a control directly addresses the threat.
	ThreatStatusMitigated ThreatStatus = "Mitigated"
)

// Severity represents the criticality of a threat.
type Severity string

const (
	SeverityLow      Severity = "Low"
	SeverityMedium   Severity = "Medium"
	SeverityHigh     Severity = "High"
	SeverityCritical Severity = "Critical"
)

// Threat represents a single identified threat and its recommended mitigations.
type Threat struct {
	Kind        ThreatKind
	Target      string
	Description string
	Mitigations []string
	Status      ThreatStatus
	Severity    Severity
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

// FlowHasSensitiveData reports whether a data flow carries a sensitive data type.
func FlowHasSensitiveData(f *DataFlow) bool {
	for _, d := range f.DataTypes {
		if sensitiveDataTypes[strings.ToLower(d)] {
			return true
		}
	}
	return false
}

// IsSecureProtocol reports whether the protocol is one of https, tls, mtls, or ssh.
func IsSecureProtocol(protocol string) bool {
	p := strings.ToLower(protocol)
	return p == "https" || p == "tls" || p == "mtls" || p == "ssh"
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func scoreToSeverity(score int) Severity {
	switch score {
	case 0:
		return SeverityLow
	case 1:
		return SeverityMedium
	case 2:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}

func componentHasSensitiveData(c *Component) bool {
	for _, s := range c.Stores {
		if sensitiveDataTypes[strings.ToLower(s)] {
			return true
		}
	}
	for _, h := range c.Handles {
		if sensitiveDataTypes[strings.ToLower(h)] {
			return true
		}
	}
	return false
}

func componentSeverity(c *Component, exposed bool) Severity {
	hasSensitive := componentHasSensitiveData(c)
	isPrivileged := c.Environment == "k8s" || c.Environment == "container" || c.Environment == "vm" ||
		c.Type == "api" || c.Type == "gateway" || c.Type == "load-balancer"
	score := boolToInt(exposed) + boolToInt(hasSensitive) + boolToInt(isPrivileged)
	return scoreToSeverity(score)
}

func flowSeverity(f *DataFlow, crossing, sensitive bool) Severity {
	insecure := !IsSecureProtocol(f.Protocol)
	score := boolToInt(crossing) + boolToInt(sensitive) + boolToInt(insecure)
	return scoreToSeverity(score)
}

func appendComponentThreats(out []*Threat, c *Component, exposed bool) []*Threat {
	sev := componentSeverity(c, exposed)
	hasData := len(c.Stores) > 0 || len(c.Handles) > 0

	if exposed || c.Type == "api" || c.Type == "gateway" || c.Type == "load-balancer" {
		out = append(out, &Threat{
			Kind:        Spoofing,
			Target:      c.ID,
			Description: fmt.Sprintf("%s may be spoofed by an attacker", c.Name),
			Mitigations: []string{
				"Enforce strong authentication and caller identity verification",
				"Use mutual TLS or service identity tokens",
			},
			Status:   ThreatStatusOpen,
			Severity: sev,
		})
	}

	if hasData {
		out = append(out, &Threat{
			Kind:        Tampering,
			Target:      c.ID,
			Description: fmt.Sprintf("%s processes or stores data that could be tampered with", c.Name),
			Mitigations: []string{
				"Validate and sanitize all inputs",
				"Use integrity checks such as checksums or signatures",
				"Restrict write access to authorized actors",
			},
			Status:   ThreatStatusOpen,
			Severity: sev,
		})
	}

	if hasData {
		out = append(out, &Threat{
			Kind:        Repudiation,
			Target:      c.ID,
			Description: fmt.Sprintf("Actions on %s may not be provably logged", c.Name),
			Mitigations: []string{
				"Implement immutable audit logging",
				"Include non-repudiable timestamps and identities",
				"Protect logs from tampering",
			},
			Status:   ThreatStatusOpen,
			Severity: sev,
		})
	}

	if hasData {
		out = append(out, &Threat{
			Kind:        InformationDisclosure,
			Target:      c.ID,
			Description: fmt.Sprintf("%s may leak stored or processed data", c.Name),
			Mitigations: []string{
				"Encrypt data at rest and in transit",
				"Apply least-privilege and need-to-know access",
				"Mask, tokenize, or redact sensitive fields",
			},
			Status:   ThreatStatusOpen,
			Severity: sev,
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
			Status:   ThreatStatusOpen,
			Severity: sev,
		})
	}

	if exposed || hasData || c.Type == "api" || c.Type == "gateway" || c.Type == "load-balancer" {
		out = append(out, &Threat{
			Kind:        ElevationOfPrivilege,
			Target:      c.ID,
			Description: fmt.Sprintf("An attacker may gain unauthorized privileges on %s", c.Name),
			Mitigations: []string{
				"Apply least-privilege RBAC and service accounts",
				"Use sandboxed or isolated execution environments",
				"Regularly patch and harden host and container images",
			},
			Status:   ThreatStatusOpen,
			Severity: sev,
		})
	}

	return out
}

func appendFlowThreats(out []*Threat, f *DataFlow, crossing, sensitive bool) []*Threat {
	base := fmt.Sprintf("Data flow %s from %s to %s", f.ID, f.Source, f.Target)
	sev := flowSeverity(f, crossing, sensitive)

	spoofMits := []string{
		"Validate the source identity before processing",
		"Use mutual TLS or signed tokens for callers",
	}
	if f.Auth == "" {
		spoofMits = append([]string{"Require authentication for this flow"}, spoofMits...)
	}
	spoofStatus := ThreatStatusOpen
	if f.Auth != "" {
		spoofStatus = ThreatStatusMitigated
	}
	out = append(out, &Threat{
		Kind:        Spoofing,
		Target:      f.ID,
		Description: base + " may be spoofed",
		Mitigations: spoofMits,
		Status:      spoofStatus,
		Severity:    sev,
	})

	tampMits := []string{
		"Validate message integrity",
		"Use signed or MAC-protected payloads",
	}
	if !IsSecureProtocol(f.Protocol) {
		tampMits = append([]string{"Encrypt the channel with TLS"}, tampMits...)
	}
	tampStatus := ThreatStatusOpen
	if IsSecureProtocol(f.Protocol) {
		tampStatus = ThreatStatusMitigated
	}
	out = append(out, &Threat{
		Kind:        Tampering,
		Target:      f.ID,
		Description: base + " may be tampered with in transit",
		Mitigations: tampMits,
		Status:      tampStatus,
		Severity:    sev,
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
		Status:   ThreatStatusOpen,
		Severity: sev,
	})

	infoMits := []string{
		"Minimize data shared over this flow",
		"Apply field-level encryption or tokenization",
	}
	if !IsSecureProtocol(f.Protocol) {
		infoMits = append([]string{"Encrypt data in transit using TLS"}, infoMits...)
	}
	if sensitive {
		infoMits = append([]string{"Mask or tokenize sensitive data fields"}, infoMits...)
	}
	infoStatus := ThreatStatusOpen
	if IsSecureProtocol(f.Protocol) && !sensitive {
		infoStatus = ThreatStatusMitigated
	}
	out = append(out, &Threat{
		Kind:        InformationDisclosure,
		Target:      f.ID,
		Description: base + " may leak sensitive information",
		Mitigations: infoMits,
		Status:      infoStatus,
		Severity:    sev,
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
		Status:      ThreatStatusOpen,
		Severity:    sev,
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
		Status:      ThreatStatusOpen,
		Severity:    sev,
	})

	return out
}
