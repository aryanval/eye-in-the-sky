# EITS-ENTRA-001: Service principal credential addition followed by app role assignment

This design was specified before the SQL implementation. It identifies a directory administrative sequence, not observed use of the added credential.

## Public fields and exact predicate

Use Microsoft Graph v1.0 directory audit records with `activityDateTime`, `activityDisplayName`, `category`, `result`, `initiatedBy.user.id`, and `targetResources[].type/id`. The two exact activity names are `Add service principal credentials` and `Add app role assignment to service principal`; both are listed in Microsoft's [audit activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities). The [directoryAudit](https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0), [targetResource](https://learn.microsoft.com/en-us/graph/api/resources/targetresource?view=graph-rest-1.0), and [initiator](https://learn.microsoft.com/en-us/graph/api/resources/auditactivityinitiator?view=graph-rest-1.0) definitions supply the field contracts.

Require both records to report `result=success` and `category=ApplicationManagement`. Match an identical nonempty `ServicePrincipal` target object ID and the same nonempty initiating user object ID inside the same explicit collection tenant. The later assignment must occur strictly after the credential operation and no more than 30 minutes later. Target arrays are searched rather than assuming a particular position. No email, display name, IP, appId, or ambiguous modified-property value is used as an identity join. SQL emits both exact supporting event UIDs and the matched target.

## Security relevance and observation boundary

A credential change followed by application-role assignment can combine persistent application authentication with changed application authorization. These activities are worth reviewing together. ATT&CK T1098.001 (Additional Cloud Credentials) describes the credential persistence concern; this is a behavioral association, not proof that a technique succeeded.

Observed facts are two successful named operations, their exact target/initiator identifiers, tenant and timestamps. Inference is that the administrative sequence warrants investigation. The generic schema does not guarantee which of several service-principal targets is an assignment recipient versus a resource principal. Therefore a matching target only proves both audit records mention the same service principal; effective app permissions, role sensitivity, assignment direction, credential material, subsequent credential use, actor intent and authorization remain unresolved. This limitation is explicit in each finding.

## Benign workflows and tuning

Approved application provisioning, credential rotation followed by an unrelated authorized app-role assignment, and a shared administrator changing a resource principal can look identical. These produce deliberate false positives in the corpus. Review change approval, application ownership, exact assignment principal/resource/appRoleId and credential history. No allowlists or suppression based on names ship. A future exception needs tenant, object ID, authorized workflow and expiry, and must be reevaluated against missed cases.

## Coverage and limitations

Requires retained successful audit records for both operations, explicit collection tenant, immutable initiating user and target IDs, supported activity names and timestamps. Application-initiated changes, different administrators, different target typing, missing telemetry, reversed order, equal timestamps and delays beyond 30 minutes are outside this rule. `modifiedProperties` is retained but not interpreted as a universal layout. Source schemas establish representation; synthetic records do not establish real-world completeness or an exact live emitted payload for these activities. There is no cross-cloud identity join and no live tenant validation.

The deterministic corpus includes malicious, authorized lookalike, ambiguous, missing-event, missing-field, delayed, failed-operation, different-user, different-target and time-boundary cases plus background events. Ground truth is in `evaluation/entra-ground-truth.json`, separate from inputs. One baseline is retained; no tuning candidate is claimed. Precision/recall describe only these deliberately imperfect fixtures.
