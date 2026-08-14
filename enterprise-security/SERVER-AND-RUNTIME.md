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

# Server and Runtime Security

VVAH does not probe a live server, enumerate ports, authenticate to an
operating system, crawl a deployed application, inspect cloud control planes,
or execute the target. Complete these checks separately, only within explicit
authorization and an approved testing window.

## Start with a runtime inventory

Record the production facts that source analysis cannot prove:

- Service, business function, owner, criticality, and environment.
- Deployed artifact digest and its source revision.
- Public, partner, internal, management, and service-to-service endpoints.
- Host, VM, container, function, cluster, platform, and cloud-account context.
- User, administrator, workload, deployment, monitoring, and break-glass
  identities.
- Data stores, queues, caches, object stores, secrets, keys, and external
  dependencies.
- DNS, certificates, gateways, proxies, load balancers, WAF/CDN, firewalls,
  routes, private connectivity, and egress paths.
- Logging, metrics, traces, audit sources, alert routes, backups, and recovery
  dependencies.

Compare expected state with observed state. Undocumented exposure or drift is
a finding even when the individual configuration appears secure.

## Authorized assessment sequence

### 1. External exposure and edge

- Confirm DNS ownership, certificate validity and lifecycle, supported TLS,
  redirect behavior, security headers, edge routing, and origin protection.
- Verify that only intended services and management paths are reachable from
  each relevant trust zone.
- Review CDN, WAF, API gateway, bot, abuse, and denial-of-service controls,
  including bypass paths to the origin.
- Confirm egress restrictions and monitoring for high-risk workloads.

### 2. Authenticated host and platform review

- Verify supported OS/runtime versions, missing security updates, installed
  packages, enabled services, listening sockets, local firewall state, and
  hardening-baseline compliance.
- Review privileged groups, service accounts, remote administration,
  scheduled tasks, startup mechanisms, file permissions, credential storage,
  and audit configuration.
- Confirm EDR/runtime protection health, tamper protection, telemetry delivery,
  disk encryption, secure boot where required, and time synchronization.
- Review exceptions individually; unauthenticated network scans alone cannot
  establish host patch or configuration state.

### 3. Containers and orchestration

- Link the running workload to an immutable image digest and source/build
  provenance.
- Evaluate image vulnerabilities, base-image support, package inventory,
  secrets, signatures, and admission policy.
- Review runtime user, capabilities, seccomp or equivalent controls,
  filesystem mutability, host mounts, device access, resource limits, and
  metadata-service access.
- For Kubernetes, assess RBAC, workload identity, service accounts, pod
  security, admission, network policy, secrets, etcd/control-plane audit,
  node configuration, and namespace/tenant isolation.

### 4. Cloud and managed services

- Compare deployed resources with infrastructure-as-code and approved
  architecture; investigate unmanaged resources and drift.
- Review organization controls, IAM, public access, network boundaries,
  encryption/key ownership, logging, backup, replication, retention, and
  service-specific security settings.
- Identify implicit trust created by resource policies, cross-account roles,
  managed identities, metadata services, CI/CD credentials, and third-party
  integrations.
- Validate preventive policies and detective controls using approved control
  tests, not configuration presence alone.

### 5. Deployed application and API

- Build the runtime route/API inventory and compare it with VVAH's discovered
  entry points.
- Exercise authentication, authorization, tenant isolation, session handling,
  input and file processing, outbound requests, rate limits, workflow abuse,
  concurrency, error handling, and sensitive-data exposure.
- Include negative and cross-role tests. A successful happy-path test does not
  validate authorization.
- Keep automated dynamic testing within rate, data, account, and environment
  constraints approved by the service owner.

### 6. Identity and secrets

- Review effective privileges rather than role names or intended policies.
- Check human, workload, deployment, support, and emergency access paths.
- Verify MFA, credential age, rotation, revocation, federation, conditional
  access, separation of duties, and access-review evidence.
- If source or history exposes a credible secret, treat it as compromised:
  contain, rotate/revoke, inspect use, and document the incident decision.

### 7. Detection and response validation

- For each material VVAH/runtime attack path, identify the preventive control,
  expected telemetry, alert, response action, and owner.
- Generate safe, approved test signals and trace them end-to-end through
  collection, enrichment, detection, notification, and case creation.
- Verify retention and correlation fields needed for investigation.
- Exercise containment, credential revocation, artifact rollback, and recovery
  for high-impact services.

## Combining runtime evidence with VVAH

Runtime evidence can change a VVAH finding in either direction:

- A source-level path may be unreachable in production because a verified
  control breaks it. Record the control, evidence, owner, and monitoring before
  reducing priority.
- A moderate source issue may become critical when the deployed service is
  internet-facing, highly privileged, multi-tenant, or connected to sensitive
  data.
- A code fix may be insufficient when stale artifacts, alternate routes,
  cloud permissions, cached data, exposed secrets, or vulnerable dependencies
  preserve the original attack path.
- No code finding can compensate for an unknown asset, unsupported host,
  public administrative interface, excessive privilege, or absent detection.

The final assessment should state both source conclusions and deployed-state
conclusions, including uncertainty and deferred scope.
