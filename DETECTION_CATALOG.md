# Detection catalog

Six original SQL detections execute through the same rule registry and evidence
interface. The two preserved AWS rules below have metadata in
[catalog.json](src/eits/rules/catalog.json). Their recorded-time window is: **0 < elapsed <= 1,800 seconds**. Equal timestamps
do not establish ordering. Unknown outcomes do not satisfy success predicates.
Severity denotes investigation priority, not a proven malicious verdict.

## EITS-AWS-001 — New access key used for AdministratorAccess policy attachment

**Version:** 1.0.0. **Severity:** high. **Source:** AWS CloudTrail IAM management events.

The rule correlates a successful `CreateAccessKey` with a successful
`AttachUserPolicy` or `AttachRolePolicy` in the same account within 30 minutes.
The issued `responseElements.accessKey.accessKeyId` must exactly equal the later
caller `userIdentity.accessKeyId`. The attached policy must exactly equal
`arn:aws:iam::aws:policy/AdministratorAccess`.

The [executable SQL](src/eits/sql/EITS-AWS-001.sql) is the exact logic. No identity
guess is made from a username, actor ARN or IP. The creator can differ from the
credential owner; the policy recipient can differ from both.

**Evidence fields:** event IDs/times, account, both `userIdentity` objects,
created access-key ID/user name, request `policyArn`, `userName`/`roleName`, and
outcome/error fields. The finding exposes the matching key, policy target and
elapsed seconds; its raw references retain every original value.

**Why it matters:** a new persistent credential immediately performs a powerful
permission assignment. Behavioral mappings are
[T1098.001 Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
and [T1098.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/).
These mappings describe behavior, not intent.

**Expected false positives:** authorized bootstrap and administrative credential
rotation. Case-06 is deliberately indistinguishable on the required fields from
an unauthorized attachment; a detector cannot recover an approval ticket that
isn't in its evidence.

**Tuning:** investigate creator, owner and recipient independently. A future
exception would need an explicit account, actor, target, expiry and rationale,
followed by re-evaluation. There are no shipped allowlists or label-driven
suppressions.

**Limits:** the exact policy is in the commercial AWS partition. Other policies,
inline grants, delayed use, missing key IDs and STS credential chains are outside
the implemented match. A successful attachment does not establish a new effective
permission, due to existing permissions, boundaries and other policy controls.
The rule cannot prove key theft, persistence duration, malicious intent, lack of
authorization or subsequent use of the attached policy.

## EITS-AWS-002 — Logging stop followed by public administrative-port ingress

**Version:** 1.0.0 baseline/default. **Severity:** high.
**Sources:** CloudTrail management events for CloudTrail and EC2.

The rule joins a successful `StopLogging` to a successful
`AuthorizeSecurityGroupIngress` within 30 minutes. Account, principal ID and
caller access-key ID must all match and be present. Within the same
`requestParameters.ipPermissions.items` entry, it requires either `0.0.0.0/0`
or `::/0`, combined with protocol `-1` (all protocols) or TCP (`tcp`/`6`) whose
inclusive port range contains 22 or 3389.

The [baseline SQL](src/eits/sql/EITS-AWS-002.sql) expands permissions before CIDRs,
so a public web rule plus a separate private SSH rule does not accidentally match.

**Evidence fields:** event IDs/times, account, principal ID, access-key ID, trail
name/ARN, security-group ID, permission index, CIDR, protocol, port bounds, and
outcome/error fields. Every qualifying permission remains in predicate evidence.

**Why it matters:** the same observed identity/credential requests reduced trail
logging and broader administrative network permissions. Current mappings are
[T1685.002 Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/)
and [T1686.001 Cloud Firewall](https://attack.mitre.org/techniques/T1686/001/).

**Expected false positives:** authorized maintenance, trail migration and
emergency access. Case-18 is authorized in the synthetic scenario; that approval
is not encoded in the log events. Case-19 additionally records a logging restart.

**Tuning experiment:** the opt-in `restart-aware` revision 1.1.0 adds `NOT EXISTS`
for a successful `StartLogging` with the exact same account/trail identifier
strictly between stop and ingress. The actor performing restoration need not be
the original actor. Name/ARN aliases are not reconstructed. See the
[candidate SQL](src/eits/sql/EITS-AWS-002-restart-aware.sql) and
[candidate metadata](src/eits/rules/restart-aware.json).

The candidate removes case-19's false positive, but it also suppresses malicious
case-16, where the attacker restores logging before changing ingress. Its lower
recall is retained in [EVALUATION.md](EVALUATION.md); baseline remains the default.

**Limits and unresolved facts:** the rule cannot show whether this trail covered
the EC2 activity, whether other collection continued, or whether the resource was
reachable from the internet. Routing, attached resources, host firewalls and
listeners are not provided. It cannot show a connection, exploitation or intent.
Only the documented `ipPermissions.items` representation is supported. Missing
identity/credential values, other sessions and delayed changes can produce misses.

[AWS Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
is independent of trails. A trail stop therefore does not establish that all
CloudTrail collection stopped. Fixture sequences model management-event
availability such as Event History, not guaranteed delivery from the stopped trail.

## Investigation output

`eits explain FINDING_ID` includes exact rule metadata, field predicates,
supporting events, verified source references, a context timeline, observed facts,
a marked inference and unresolved questions. `eits event EVENT_ID` opens a raw
record. Summaries and fixture ground-truth labels are never substituted for source
evidence.

## Phase 2 detections

These four designs document exact public fields, security relevance, benign
workflows and unresolved facts before the executable predicates. Three correlate
ordered events with **0 < elapsed <= 1,800 seconds**; one evaluates a single
policy-change record. All require explicit successful outcomes.

| Rule | Source | Supporting events | Design, metadata and executable SQL |
|---|---|---:|---|
| EITS-AZURE-001 | Azure Activity | 2 | [Diagnostic-setting deletion followed by role assignment](docs/detections/EITS-AZURE-001.md) |
| EITS-ENTRA-001 | Entra directory audit | 2 | [Service-principal credential addition followed by app-role assignment](docs/detections/EITS-ENTRA-001.md) |
| EITS-GCP-001 | GCP Audit | 2 | [New service-account key used to set project IAM policy](docs/detections/EITS-GCP-001.md) |
| EITS-GCP-002 | GCP Audit | 1 | [Public principal added to bucket object-access policy](docs/detections/EITS-GCP-002.md) |

Azure role assignment does not imply an administrator role. The Entra generic
record does not establish assignment direction, role sensitivity or credential
use. GCP SetIamPolicy can remove permissions; a public-principal delta does not
prove effective public access or data exposure. Those limits remain explicit in
observed facts, inference and unresolved questions. There is no cross-cloud
identity correlation.

Every rule has malicious, benign, ambiguous, missing-telemetry and background
fixtures. [EVALUATION.md](EVALUATION.md) reports retained FP/FN behavior. No Phase 2
rule was tuned against scenario labels; no alternate candidate is hidden. The
original AWS restart-aware candidate remains available and is not a seventh rule.
