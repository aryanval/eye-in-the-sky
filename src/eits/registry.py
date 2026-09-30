"""Data-driven rule revisions and evidence contracts; no provider dispatch."""

import copy
import json
from importlib.resources import files


def resource(path):
    return files("eits").joinpath(path).read_text()


class RuleRegistry:
    """Resolved revision catalogs with an injectable SQL resource loader.

    An evidence contract declares either ordered scalar ``columns`` or one
    ``list_column``. The query defines evidence order, including sequence order.
    """

    def __init__(self, catalogs, *, resource_loader=resource):
        self._catalogs = copy.deepcopy(catalogs)
        self._resource_loader = resource_loader
        if not isinstance(self._catalogs, dict) or not self._catalogs:
            raise ValueError("rule registry must define revisions")
        for revision, rules in self._catalogs.items():
            if not isinstance(revision, str) or not revision or not isinstance(rules, dict):
                raise ValueError("invalid rule revision")
            for rule_id, metadata in rules.items():
                if not isinstance(rule_id, str) or not rule_id or not isinstance(metadata, dict):
                    raise ValueError("invalid rule metadata")
                for key in ("version", "provider", "source", "sql_path", "title", "severity"):
                    if not isinstance(metadata.get(key), str) or not metadata[key]:
                        raise ValueError(f"rule {rule_id} requires {key}")
                for key in ("attack", "observed", "inferred", "cannot_establish"):
                    if key not in metadata:
                        raise ValueError(f"rule {rule_id} requires {key}")
                contract = metadata.get("evidence")
                if not isinstance(contract, dict):
                    raise ValueError(f"rule {rule_id} requires an evidence contract")
                if set(contract) == {"columns"}:
                    columns = contract["columns"]
                    if (
                        not isinstance(columns, list)
                        or not columns
                        or any(not isinstance(column, str) or not column for column in columns)
                        or len(set(columns)) != len(columns)
                    ):
                        raise ValueError("evidence columns must be nonempty and unique")
                elif set(contract) == {"list_column"}:
                    if not isinstance(contract["list_column"], str) or not contract["list_column"]:
                        raise ValueError("evidence list_column must be a nonempty string")
                else:
                    raise ValueError("evidence requires either columns or list_column")

    @classmethod
    def packaged(cls):
        catalogs = {}
        for revision, paths in json.loads(resource("rules/registry.json")).items():
            rules = {}
            for path in paths:
                for rule_id, metadata in json.loads(resource(path)).items():
                    rules.setdefault(rule_id, {}).update(metadata)
            catalogs[revision] = rules
        return cls(catalogs)

    def revisions(self):
        return tuple(self._catalogs)

    def for_source(self, provider, source):
        """Keep a single-source evaluation focused as the global catalog grows."""
        return RuleRegistry(
            {
                revision: {
                    rule_id: metadata
                    for rule_id, metadata in rules.items()
                    if (metadata["provider"], metadata["source"]) == (provider, source)
                }
                for revision, rules in self._catalogs.items()
            },
            resource_loader=self._resource_loader,
        )

    def catalog(self, revision):
        try:
            return copy.deepcopy(self._catalogs[revision])
        except KeyError as exc:
            raise ValueError("unknown rule revision") from exc

    def sql(self, rule_id, revision):
        return self._resource_loader(self.catalog(revision)[rule_id]["sql_path"])
