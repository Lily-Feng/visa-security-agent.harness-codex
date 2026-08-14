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

# Post-Scan Enterprise Playbook

This playbook begins after VVAH produces its Markdown, SARIF, error log, and run
manifest. It ends only when each finding and coverage gap has an evidence-based
decision.

## Gate 1: Establish assessment integrity

- Record target repository, commit, branch, scan area, application identifier,
  profile/configuration hash, model roles, start/end time, and operator.
- Preserve the run manifest and generated artifacts together.
- Review scan health, non-fatal errors, excluded paths, generated/binary
  content, submodules, vendored code, and deferred areas.
- Confirm the scanned source maps to the artifact and environment under review.

**Exit criterion:** the team can state exactly what was and was not analyzed.

## Gate 2: Triage every candidate

For each finding:

1. Reproduce the source-to-sink or control-bypass reasoning manually.
2. Confirm attacker influence, required access, trust boundaries, reachable
   deployment path, affected assets, and realistic impact.
3. Check whether a verified production control interrupts the path.
4. Look for alternate routes, shared root causes, duplicate findings, and
   exploit chains.
5. Classify the result as accepted, rejected, needs evidence, duplicate, or
   risk accepted. Preserve the rationale.

Do not close a finding solely because a model or one scanner disagrees with it.

**Exit criterion:** every candidate has an evidence-backed disposition and
accountable owner.

## Gate 3: Expand beyond source

- Use [CONTROL-MATRIX.md](CONTROL-MATRIX.md) to identify affected control
  domains.
- Complete the authorized checks in
  [SERVER-AND-RUNTIME.md](SERVER-AND-RUNTIME.md).
- Run deterministic source, dependency, secret, IaC, image, host, cloud, and
  runtime checks appropriate to the service.
- Evaluate identity, data, logging, response, and recovery dependencies for
  each credible attack path.

**Exit criterion:** source findings and deployed-state evidence form one
coherent risk picture.

## Gate 4: Design remediation

- Fix the root control, not only the reported input or symptom.
- Prefer centralized, deny-by-default security controls over repeated local
  checks.
- Include code, configuration, identity, data, platform, telemetry, and
  operational changes needed to break the complete path.
- Define regression tests and negative tests before implementation.
- Identify rollout, compatibility, migration, rollback, and emergency
  containment requirements.
- For high-impact issues, obtain independent security review of the plan.

**Exit criterion:** the planned changes break the attack path without creating
an unowned operational or compatibility risk.

## Gate 5: Verify the fix

VVAH's remediation and validation outputs are review inputs. They do not
replace engineering verification.

- Review the diff and generated remediation DTO.
- Build the exact candidate artifact.
- Run unit, integration, regression, and security tests, including negative and
  bypass cases.
- Re-run relevant static, dependency, secret, IaC, and image checks.
- Validate the candidate in a representative non-production environment.
- Confirm logging and alert behavior for both allowed and denied activity.
- Verify that alternate routes and older deployable artifacts do not preserve
  the issue.

**Exit criterion:** repeatable evidence demonstrates that the root attack path
and reasonable bypasses are blocked.

## Gate 6: Deploy and observe

- Use an approved, traceable artifact and change process.
- Apply required secret rotation, identity-policy, infrastructure, edge, and
  monitoring changes in the correct order.
- Use staged rollout and rollback controls appropriate to service criticality.
- Confirm deployed digest/configuration and execute focused post-deployment
  checks.
- Monitor security and reliability signals through the defined observation
  period.

**Exit criterion:** the intended artifact and controls are active in the target
environment without unacceptable regression.

## Gate 7: Close or accept residual risk

A closure record should include:

- Finding and affected asset identifiers.
- Source and deployed artifact revisions.
- Root cause and attack path.
- Code and non-code corrective actions.
- Test, scan, deployment, and monitoring evidence.
- Remaining uncertainty and residual risk.
- Reviewer and closure authority.
- For an exception: compensating controls, monitoring, accountable owner,
  expiration, and re-review trigger.

**Exit criterion:** closure is independently understandable and time-bound risk
is visible to the organization.

## Immediate escalation conditions

Use the organization's incident process rather than ordinary vulnerability
workflow when evidence indicates possible active exploitation, exposed working
credentials, unauthorized access, sensitive-data exposure, persistence,
malicious dependency/build activity, or loss of audit integrity.

Do not continue invasive testing on a potentially compromised production
system without incident-command authorization.
