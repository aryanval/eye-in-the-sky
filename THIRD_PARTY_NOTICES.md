# Third-party notices

`fixtures/aws/official/sample-*.json` consists of selected JSON examples extracted
from [AWS CloudTrail log file examples](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html).
Copyright Amazon.com, Inc. or its affiliates. No vendor endorsement is implied.

The [AWS Site Terms](https://aws.amazon.com/terms/) license documentation hosted
on docs.aws.amazon.com under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/legalcode.en)
and embedded code under [MIT-0](https://opensource.org/license/mit-0).
These retained documentation excerpts are distributed with CC BY-SA 4.0 attribution;
the project's proprietary terms do not replace their upstream terms.
The examples were extracted from HTML code blocks without changing event values.
The manifest identifies the retrieval timestamp, source page hash, each file hash,
selection procedure, source URL and limitations.

The original Python, SQL, independently generated synthetic fixtures and
documentation are proprietary, with all rights reserved under [LICENSE](LICENSE).
DuckDB and pytz are installed dependencies, not vendored source. Their package
distributions retain their own license notices.

## Microsoft Azure REST API example

`fixtures/azure/activity/official/GetActivityLogsFiltered.source.json` retains the
original [Microsoft REST API specification example](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/monitor/resource-manager/Microsoft.Insights/Insights/stable/2015-04-01/examples/GetActivityLogsFiltered.json).
`sample-01.json` is an exact byte extraction of its response body; event values
and internal whitespace are unchanged. Copyright Microsoft Corporation.
The upstream Microsoft repository's MIT permission/copyright notice is retained in
`fixtures/azure/activity/official/LICENSE.microsoft.txt`. Its manifest records
source/retrieval/extraction information and both hashes. See
[Azure source documentation](docs/sources/azure-activity.md).

## Microsoft Graph documentation excerpts

The `documentation/` directories under `fixtures/azure/entra-signin` and
`fixtures/azure/entra-audit` retain unmodified response excerpts from public
Microsoft Graph v1.0 documentation. Copyright Microsoft Corporation and
contributors. The documentation repository uses
[CC BY 4.0](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/LICENSE)
with a separate [MIT code license](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/LICENSE-CODE).
Original MIT notices, source URLs, excerpt hashes and extraction details accompany
the excerpts. Abbreviations and presentation errors remain unchanged; these are
not executable official fixtures. See [Entra source documentation](docs/sources/entra.md).

## Google documentation excerpts

`fixtures/gcp/documentation` retains unchanged code-block text from
[Google service-account audit examples](https://docs.cloud.google.com/iam/docs/audit-logging/examples-service-accounts).
Copyright Google LLC. Google's [site policies](https://developers.google.com/terms/site-policies)
and page notices identify CC BY 4.0 for documentation and Apache-2.0 for code
samples, subject to specific notices. The Apache-2.0 text is retained in
`fixtures/gcp/documentation/LICENSE-APACHE-2.0.txt` from
[Apache](https://www.apache.org/licenses/LICENSE-2.0.txt). Attribution, source URL, extraction,
retrieval date, page hash and excerpt hashes are in `provenance.json`. Vendor
abbreviations and a trailing comma remain unchanged. These are documentation
evidence, not complete official fixtures. See [GCP source documentation](docs/sources/gcp.md).

No vendor endorsement is implied. Original project Python/SQL and independently
generated synthetic records are subject to the proprietary project terms in
[LICENSE](LICENSE); those terms do not relicense any retained vendor material.
