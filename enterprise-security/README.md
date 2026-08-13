<!--
Copyright 2026 Visa, Inc.
Modifications Copyright 2026 Lily Feng.
Modified by Lily Feng in 2026 for independent security guidance.

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

# Enterprise Security Companion

VVAH is an agentic static application security testing pipeline. It examines
repository content and reasons about attack paths, exploitability, remediation,
and fix quality. It does **not** establish that the deployed service, host,
cloud account, identity plane, network, or operating process is secure.

This companion turns a VVAH code scan into one input to a broader enterprise
security assessment. It is guidance, not an additional scanner, certification,
or authorization to test a system.

## Use this after every VVAH scan

1. Confirm what source revision, repository paths, generated artifacts, and
   excluded files VVAH actually reviewed.
2. Triage the Markdown and SARIF findings using the application threat model
   and production exposure, not CVSS alone.
3. Map every relevant finding and every unreviewed surface to the control
   domains in [CONTROL-MATRIX.md](CONTROL-MATRIX.md).
4. Perform the authorized runtime, host, identity, cloud, supply-chain, and
   operational checks in [SERVER-AND-RUNTIME.md](SERVER-AND-RUNTIME.md).
5. Take accepted findings through the evidence and closure gates in
   [POST-SCAN-PLAYBOOK.md](POST-SCAN-PLAYBOOK.md).
6. Record residual risk, exceptions, owners, deadlines, and compensating
   controls. A missing owner is an unresolved finding.

## What VVAH covers and what remains

| Security question | VVAH contribution | Additional enterprise evidence required |
|---|---|---|
| Can untrusted input reach a dangerous operation? | Source-level entry-point, sink, and exploit-path reasoning | Runtime route inventory, deployed configuration, gateway and WAF behavior, authenticated tests |
| Are authorization decisions correct? | Code-path and business-logic analysis | Identity-provider policy, role assignments, tenant isolation tests, privileged-access review |
| Are dependencies and build inputs trustworthy? | May identify risky use visible in source | SCA/SBOM, provenance, signatures, dependency policy, build-service and artifact-registry controls |
| Is the server patched and hardened? | Configuration-as-code clues when committed | Asset inventory, authenticated host scan, patch state, baseline compliance, EDR coverage |
| Is the internet-facing service configured safely? | Source and repository configuration | External exposure inventory, TLS/DNS/CDN/WAF checks, DAST/API assessment, certificate lifecycle |
| Are cloud resources protected? | IaC and application credential-flow analysis | Deployed-state CSPM/CNAPP evidence, IAM review, organization policies, runtime drift detection |
| Are secrets protected? | Source-level secret patterns and unsafe handling | Secret manager policy, rotation evidence, CI log review, repository history and incident response |
| Will defenders detect exploitation? | Logging gaps visible in code | SIEM coverage, alert tests, telemetry retention, on-call routing, response exercises |
| Is the fix production-safe? | Candidate patch and model-based validation | Human review, build, tests, regression/security tests, staged deployment, runtime verification |

## Enterprise security domains

### Application and API security

- Maintain an application-level threat model with assets, trust boundaries,
  sensitive actions, abuse cases, and security invariants.
- Combine VVAH with deterministic SAST, software composition analysis, secret
  scanning, API-schema review, and targeted authorized dynamic testing.
- Test authentication, authorization, tenant isolation, session management,
  rate limits, input validation, file handling, outbound requests, and error
  behavior in the deployed environment.
- Treat business-logic abuse and privileged workflows as first-class test
  areas; signature-based scanners routinely under-cover them.

### Identity and privileged access

- Inventory human, workload, machine, emergency, and third-party identities.
- Require phishing-resistant MFA for privileged access where supported.
- Enforce least privilege, separation of duties, short-lived credentials, and
  periodic access recertification.
- Review service-to-service authorization and workload identity independently
  of interactive user authentication.
- Monitor and tightly govern break-glass access.

### Host, container, and endpoint security

- Maintain an authoritative asset inventory and accountable owner for every
  supported production asset.
- Verify OS and package patch state with authenticated evidence.
- Apply hardened baselines, minimize installed services, restrict
  administration paths, and prevent configuration drift.
- Scan container images and verify provenance before deployment; also inspect
  the running workload because deployed state can differ from the image.
- Confirm endpoint/runtime protection, telemetry, time synchronization,
  encrypted storage, secure boot where applicable, and recovery capability.

### Network and edge security

- Maintain expected exposure and data-flow inventories; compare them with
  observed listening services, firewall policy, routing, and cloud controls.
- Use segmentation and explicit egress policy to limit lateral movement and
  data exfiltration.
- Verify DNS, certificate, TLS, CDN, load-balancer, reverse-proxy, WAF, API
  gateway, and denial-of-service protections in their deployed state.
- Restrict management planes to controlled paths and separately monitored
  administrative identities.

### Cloud, platform, and Kubernetes security

- Compare infrastructure-as-code with deployed resources and investigate
  drift rather than assuming the repository is authoritative.
- Review organization policy, IAM, network boundaries, public access, keys,
  encryption, logging, backup, and recovery settings.
- For Kubernetes, review admission controls, workload identity, RBAC, network
  policy, secrets, image policy, pod security, control-plane audit logs, and
  node hardening.
- Apply least privilege to CI/CD and deployment identities, not only runtime
  workloads.

### Software supply chain and CI/CD

- Produce an SBOM for releasable artifacts and continuously evaluate direct,
  transitive, build-time, and container dependencies.
- Pin and verify dependencies where practical; protect package namespaces and
  internal registries against substitution.
- Separate build and release authority, protect branches and environments,
  require review, and keep signing keys out of general build jobs.
- Preserve artifact provenance and promote immutable artifacts between
  environments instead of rebuilding them.
- Treat repository instructions, dependency lifecycle hooks, generated code,
  and agent-consumed content as potentially hostile inputs.

### Data protection and privacy

- Classify data and document where it is collected, processed, transmitted,
  cached, logged, backed up, and deleted.
- Minimize sensitive data and enforce purpose, retention, residency, and
  deletion requirements.
- Use managed encryption and key lifecycle controls appropriate to the threat
  model; test restoration, rotation, and revocation.
- Prevent credentials, regulated data, and realistic production records from
  entering model prompts, logs, test fixtures, or scan artifacts without an
  approved handling path.

### Detection, response, resilience, and recovery

- Define security telemetry requirements alongside each sensitive action and
  trust boundary.
- Validate that high-value events reach the intended detection platform with
  useful identity, tenant, source, target, outcome, and correlation context.
- Test alert logic and escalation routes; a configured rule without a tested
  signal path is not evidence of detection.
- Maintain incident playbooks, forensic retention, containment mechanisms,
  dependency and credential revocation procedures, and communications plans.
- Exercise backup restoration, regional/service failover, and security
  recovery objectives.

### Governance and assurance

- Assign a business owner, technical owner, security owner, data owner, and
  operational owner for the assessed service.
- Define risk acceptance authority and expiration. Exceptions must be scoped,
  time-bound, monitored, and supported by compensating controls.
- Preserve reproducible evidence: source revision, scan configuration, model
  roles, tool versions, runtime targets, timestamps, approvals, test results,
  and deployment identifiers.
- Track coverage and uncertainty as carefully as confirmed findings.
- Require independent review for high-impact findings and material changes to
  authentication, authorization, cryptography, payment, or safety controls.

## Minimum release gate

A release should not be represented as security-reviewed until the team can
answer all of the following:

- What exact source and artifact were assessed?
- What attack surfaces were reviewed, tested, excluded, or deferred?
- Which findings were accepted, rejected, fixed, mitigated, or risk-accepted?
- What evidence demonstrates that each accepted fix works?
- What deterministic code, dependency, secret, IaC, image, host, cloud, and
  runtime checks were completed?
- What production exposure and identity paths remain?
- Will exploitation create a timely, actionable signal?
- Can the service be contained and restored?
- Who owns each residual risk, and when does the decision expire?

If any answer is unknown, record it as an explicit gap rather than treating an
absence of scanner findings as assurance.
