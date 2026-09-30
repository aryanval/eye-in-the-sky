"""Explicit, optional public-documentation fetch. Never used by the runtime or demo.

Extract only AWS's JSON examples. Re-running is a deliberate source update;
review the fixture diff and source notices before committing.
"""

import hashlib
import json
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.request import urlopen

URL = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html"
ROOT = Path(__file__).resolve().parents[1]


class CodeBlocks(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.blocks, self.current = [], None

    def handle_starttag(self, tag, attrs):
        if tag == "pre":
            self.current = []

    def handle_data(self, data):
        if self.current is not None:
            self.current.append(data)

    def handle_endtag(self, tag):
        if tag == "pre" and self.current is not None:
            self.blocks.append("".join(self.current))
            self.current = None


def main():
    parser = CodeBlocks()
    with urlopen(URL, timeout=30) as response:
        page = response.read()
    parser.feed(page.decode())
    destination = ROOT / "fixtures/aws/official"
    entries = []
    for block in parser.blocks:
        try:
            value = json.loads(block)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict) or not isinstance(value.get("Records"), list):
            continue
        if not all(event.get("eventType") == "AwsApiCall" for event in value["Records"]):
            continue
        name = f"sample-{len(entries) + 1:02d}.json"
        content = block.encode()
        (destination / name).write_bytes(content)
        entries.append(
            {
                "path": name,
                "format": "cloudtrail-json",
                "sha256": hashlib.sha256(content).hexdigest(),
                "events": [e.get("eventName") for e in value["Records"]],
            }
        )
    if len(entries) < 3:
        raise SystemExit("Too few complete public API samples; review the source page")
    manifest = {
        "dataset_id": "aws-official-examples-v1",
        "provider": "aws",
        "source": "aws.cloudtrail",
        "category": "official sample",
        "source_urls": [URL],
        "license": "CC-BY-SA-4.0",
        "license_url": "https://aws.amazon.com/terms/",
        "copyright": "Amazon.com, Inc. or its affiliates",
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "source_page_sha256": hashlib.sha256(page).hexdigest(),
        "modified": False,
        "extraction": "Text from complete JSON preformatted blocks, HTML markup removed; no event values altered. Only AwsApiCall examples selected.",
        "limitations": [
            "Illustrative vendor documentation, not personal live telemetry",
            "Small sample of API events; not representative of AWS production traffic",
            "Examples may contain placeholder identifiers",
        ],
        "files": entries,
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"official_samples": len(entries), "actions": [x["events"] for x in entries]}))


if __name__ == "__main__":
    main()
