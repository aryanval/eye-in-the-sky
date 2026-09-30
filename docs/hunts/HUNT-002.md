# HUNT-002: Entra sign-in outcome and telemetry inventory

Hypothesis: repeated failed sign-ins, changing source addresses and vendor-reported risk around a user's sign-ins can expose activity worth investigating. This broad inventory includes routine successes and unresolved records; it has no alert threshold and produces no maliciousness verdict.

Required input is Graph v1.0 `signIn` objects, their explicit collection tenant, `userId`, `createdDateTime`, `status.errorCode`, `ipAddress`, and optionally `riskLevelDuringSignIn`. Missing fields remain visible as unknown. Source: [public signIn schema](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0). Executable SQL is `src/eits/sql/HUNT-002.sql`.

For each collection tenant and immutable user ID, summarize the requested number of hours starting at that user's earliest retained timestamp. The start is data-relative rather than wall-clock time, making fixture runs reproducible. Unknown timestamps are included but do not establish order. Unknown user or tenant rows remain individual leads rather than joining on an email, IP or name. Records after the displayed window are outside these counts. Every returned lead includes the exact retained event UIDs.

Failure and success counts, distinct IP count and explicit medium/high risk observations guide review. `hidden`, missing and unknown risk enums are counted as unavailable, not safe. Conditional Access success/notApplied is not proof of MFA; this Graph v1.0 subset does not prove MFA satisfaction, so MFA outcome is always unknown. Vendor risk observations are context, not independent proof.

Suspicion increases with unexplained failure bursts followed by successful access, corroborated unfamiliar-device evidence, independently verified credential exposure or unauthorized downstream actions. It decreases with approved authentication testing, expected VPN egress changes, password mistakes, known device transitions and validated authorized activity. Neither an IP change nor an elevated risk field establishes compromise.

Before calling activity malicious, obtain the user's authorization/context, authentication and device evidence, application access and directory audit evidence with exact immutable identity linkage. This query does not join clouds, infer geographic travel or assert that failed and successful attempts came from the same physical person. The synthetic input demonstrates normal, failed, risk-visible and missing-data behavior; it does not measure threat prevalence or validate a live tenant.
