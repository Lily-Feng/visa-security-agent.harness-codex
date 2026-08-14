<!--
Copyright 2026 Lily Feng.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Enterprise Security Control Matrix

Use this matrix to plan evidence after a VVAH scan. Adapt the owner names and
cadence to the organization's risk model. A tool result is evidence for a
control; it is not the control itself.

| Domain | Control objective | Minimum evidence | Typical accountable owner | Suggested cadence |
|---|---|---|---|---|
| Scope and inventory | All in-scope code, services, assets, identities, data stores, and third parties are known | Repository and artifact revisions, service catalog, asset inventory, data-flow diagram, exclusions | Service owner | Every material change and at least quarterly |
| Threat modeling | Security invariants and credible attacker paths are documented | Current threat model, abuse cases, trust boundaries, VVAH S1–S3 artifacts | Security architect and service owner | Design change and annual refresh |
| Source security | Vulnerable source paths are found and resolved | VVAH report/SARIF, deterministic SAST results, manual review record | Engineering owner | Pull request plus periodic deep scan |
| Dependencies | Known-vulnerable or untrusted components are governed | SBOM, SCA results, exception record, provenance and signature evidence | Product security and build owner | Every build plus continuous monitoring |
| Secrets | Secrets are not exposed and are rotated when compromise is possible | Secret scan including history, manager policy, rotation logs, incident decision | Identity/secrets owner | Every change plus continuous monitoring |
| Build and release | Builds are reproducible, isolated, reviewed, and traceable | Protected workflow, provenance, signed immutable artifact, approval and promotion records | Platform engineering | Every release |
| Application runtime | Deployed behavior preserves application security controls | Authorized DAST/API results, authentication and authorization tests, negative tests, route inventory | Application security | Major release and risk-based periodic test |
| Host and image | Workloads run on supported, patched, hardened platforms | Authenticated host/image scan, baseline compliance, EDR/runtime status, patch SLA | Infrastructure owner | Continuous inventory; risk-based scan cycle |
| Cloud and platform | Deployed configuration enforces intended boundaries | CSPM/CNAPP or equivalent evidence, IAM review, drift report, organization policy | Cloud/platform owner | Continuous monitoring plus quarterly review |
| Network and edge | Only intended services are reachable and egress is controlled | Exposure inventory, firewall/security-group review, TLS/DNS/CDN/WAF evidence | Network/platform owner | Continuous monitoring and every topology change |
| Identity | Human and workload privileges are least-privileged and reviewable | Role/policy export, access review, MFA evidence, privileged and break-glass logs | Identity owner | Continuous privileged monitoring; quarterly recertification |
| Data protection | Sensitive data has controlled collection, use, movement, retention, and deletion | Classification, flow map, encryption/key evidence, retention/deletion tests | Data owner and privacy | Design change plus periodic control test |
| Detection | Exploitation creates a timely, actionable signal | Logging requirements, end-to-end signal test, alert outcome, runbook and on-call routing | Detection/SOC owner | Every new critical path; scheduled control tests |
| Response | The organization can contain, investigate, notify, and recover | Incident playbook, exercise record, forensic retention, contact and escalation validation | Incident response | At least annually and after material change |
| Resilience | Security-relevant backups and recovery paths work | Restore test, failover evidence, RTO/RPO result, credential/key recovery | Reliability owner | Risk-based, at least annually |
| Vulnerability management | Findings have accountable and risk-based closure | Ticket, severity rationale, owner, SLA, fix evidence, exception approval and expiry | Vulnerability management | Continuous |
| Assurance | Claims are independently reviewable and evidence is retained | Assessment package, reviewer approval, audit trail, residual-risk statement | Risk/compliance owner | Release or assessment boundary |

## Finding-to-control mapping

For each accepted or unresolved VVAH finding, record:

| Field | Required content |
|---|---|
| Finding identity | Stable VVAH/SARIF identifier and source revision |
| Root control | The security invariant or control that failed |
| Production relevance | Deployed component, route, identity, data, and exposure |
| Evidence status | Confirmed, plausible, disproved, or unverifiable, with evidence links |
| Related controls | Host, identity, network, cloud, supply-chain, detection, and recovery dependencies |
| Corrective action | Code fix plus any required non-code changes |
| Validation plan | Static, build, test, runtime, and monitoring checks |
| Owner and due date | Accountable individual/team and risk-based deadline |
| Residual risk | What remains after remediation and why it is acceptable or not |
| Closure authority | Person or role approving closure or risk acceptance |

## Evidence quality rules

- Prefer evidence generated from the exact artifact and environment being
  approved.
- Record timestamps, versions, configuration, scope, and exclusions.
- Keep raw artifacts or immutable references, not screenshots alone.
- Separate model assertions from deterministic observations and human
  decisions.
- A passed scan with incomplete coverage remains incomplete evidence.
- A compensating control must be verified against the same attack path it is
  intended to interrupt.
