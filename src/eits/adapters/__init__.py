"""Source adapters and their explicit provider scope namespaces."""

from dataclasses import asdict, dataclass
from typing import Iterable, Protocol

from ..model import Event, NormalizationContext
from .aws import CloudTrailAdapter
from .azure_activity import AzureActivityAdapter
from .entra import EntraAuditAdapter, EntraSignInAdapter
from .gcp import GcpAuditAdapter


class SourceAdapter(Protocol):
    provider: str
    source: str
    formats: tuple[str, ...]

    def parse(self, content: bytes, format_name: str) -> Iterable[tuple[str, dict]]: ...

    def normalize(self, raw: dict, *, context: NormalizationContext | None = None) -> Event: ...

    def resolve(self, content: bytes, format_name: str, pointer: str) -> dict: ...


@dataclass(frozen=True)
class SourceSpec:
    provider: str
    source: str
    scope_types: tuple[str, ...]
    has_tenant: bool = False
    identity_scheme: str = "v2-provider-source-scope"


SOURCES = (
    SourceSpec("aws", "aws.cloudtrail", ("aws.account",), identity_scheme="v1-raw-compatible"),
    SourceSpec("azure", "azure.activity", ("azure.subscription", "azure.tenant"), True),
    SourceSpec("azure", "azure.entra.signin", ("azure.tenant",), True),
    SourceSpec("azure", "azure.entra.audit", ("azure.tenant",), True),
    SourceSpec("gcp", "gcp.audit", ("gcp.project", "gcp.organization", "gcp.folder")),
)


class AdapterRegistry:
    def __init__(self, adapters=None):
        self._adapters = {}
        defaults = (
            CloudTrailAdapter(),
            AzureActivityAdapter(),
            EntraSignInAdapter(),
            EntraAuditAdapter(),
            GcpAuditAdapter(),
        )
        for adapter in defaults if adapters is None else adapters:
            spec = self.spec(adapter.provider, adapter.source)
            if spec.source in self._adapters:
                raise ValueError(f"duplicate source adapter: {spec.source}")
            if (
                not isinstance(adapter.formats, tuple)
                or not adapter.formats
                or not all(isinstance(name, str) and name for name in adapter.formats)
                or not all(
                    callable(getattr(adapter, name, None))
                    for name in ("parse", "normalize", "resolve")
                )
            ):
                raise ValueError("adapter requires formats, parse, normalize, and resolve")
            self._adapters[spec.source] = adapter

    def spec(self, provider, source):
        spec = next((item for item in SOURCES if item.source == source), None)
        if spec is None:
            raise ValueError(f"unknown source: {source}")
        if provider != spec.provider:
            raise ValueError("manifest provider/source mismatch")
        return spec

    def get(self, provider, source):
        spec = self.spec(provider, source)
        adapter = self._adapters.get(spec.source)
        if adapter is None:
            raise ValueError(f"source adapter is reserved but not implemented: {source}")
        return adapter

    def catalog(self):
        return [
            {
                **asdict(spec),
                "implemented": spec.source in self._adapters,
                "formats": list(self._adapters[spec.source].formats)
                if spec.source in self._adapters
                else [],
            }
            for spec in SOURCES
        ]


DEFAULT_REGISTRY = AdapterRegistry()


def source_catalog():
    return DEFAULT_REGISTRY.catalog()
