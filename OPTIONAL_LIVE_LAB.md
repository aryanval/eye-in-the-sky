# Optional live lab — deferred, not executed

**Status: no personal live-cloud validation.** Phase 1 completion does not depend
on this document. No cloud account, credential, paid service or tenant was accessed
or created for the project. Validation evidence is limited to public vendor
examples and independently generated synthetic fixtures.

AWS is the first potential target for a future optional lab.
[CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
provides recent regional management events independently of a configured trail.
This source can support a small read-only management-event exercise; there is no
need to reproduce either risky detection sequence in a live account.

The future procedure is deliberately bounded:

1. Use only an easy-to-access personal AWS account controlled by the project owner.
   Keep setup bounded to 30 minutes and preserve fixture-only validation if setup
   cannot be completed without paid services.
2. Recheck current AWS documentation and any costs before selecting two or three
   benign, non-provisioning management calls. Do not grant administrative roles,
   create persistent credentials, disable logging or expose network ports merely
   to generate an alert.
3. Retrieve only those personal management events. Import them with a separate
   manifest labeled `personally generated live event`, including source method,
   timestamps, hashes, modifications and limitations.
4. Run a relevant hunt and inspect the exact raw evidence. A no-alert result is
   valid; do not fabricate a detection. The credential-use hunt may have no leads
   if the safe activity does not create a key. Select a relevant benign query in
   that later scope instead of manufacturing risky events.
5. Record which parser, fixture, dataset and personal live-event checks actually
   passed. Keep personal raw files local by default; publication would be a
   separate decision. Any modified published copy must disclose its changes.

Azure and GCP validation remain documentation/fixture based. Personal live labs
are deferred work. A successful small AWS exercise would support only the actions actually
performed; it would not establish production AWS/GCP experience or enterprise
multicloud administration.
