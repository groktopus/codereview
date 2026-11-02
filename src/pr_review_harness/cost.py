"""Versioned operator prices, bounded estimates, and pre-dispatch ceilings.

Billed, estimated, and bounded cost are separate facts: billing stays
``UNKNOWN`` unless authoritative and is never inferred from an estimate. An
estimate is observed usage times an exact operator row, labelled
``PRICE_TABLE_ESTIMATE`` with its revision. A bound is a conservative ceiling
used only to reserve room under a per-run currency ceiling. The table is
trusted external input, never fetched or verified; malformed or missing data
fails closed rather than becoming zero or an invented price. Prices are
integer microunits of the declared currency per million tokens.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

PRICE_TABLE_SCHEMA = "review-price-table.v1"
PRICE_TABLE_BASIS = "PRICE_TABLE_ESTIMATE"
TOKENS_PER_PRICE_UNIT = 1_000_000
MAX_PRICE_TABLE_BYTES = 128_000
MAX_PRICE_TABLE_ENTRIES = 1_000
MAX_UNIT_PRICE_MICROUNITS = 10**12

_CURRENCY = re.compile(r"[A-Z]{3}")
_REVISION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}")
_TOP_LEVEL_FIELDS = frozenset({"schema", "revision", "currency", "providers"})
_ENTRY_FIELDS = frozenset(
    {
        "provider_id",
        "model_id",
        "input_price_microunits_per_million_tokens",
        "output_price_microunits_per_million_tokens",
    }
)


class PriceTableError(ValueError):
    """Safe, content-free price-table validation failure."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ValueError("non-finite number")


def _bounded_text(value: Any, field: str, limit: int = 200) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise PriceTableError(f"price table {field} is invalid")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise PriceTableError(f"price table {field} is invalid")
    return value


def _price(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_UNIT_PRICE_MICROUNITS:
        raise PriceTableError(f"price table {field} is invalid")
    return value


def _token_cost(price: int, tokens: int) -> int:
    """Ceiling integer cost; never rounds a real charge down."""
    return -(-(price * tokens) // TOKENS_PER_PRICE_UNIT)


class PriceEntry:
    """One exact ``provider_id``/``model_id`` price row."""

    __slots__ = ("provider_id", "model_id", "input_price", "output_price")

    def __init__(self, provider_id: str, model_id: str, input_price: int, output_price: int) -> None:
        self.provider_id = provider_id
        self.model_id = model_id
        self.input_price = input_price
        self.output_price = output_price

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "input_price_microunits_per_million_tokens": self.input_price,
            "output_price_microunits_per_million_tokens": self.output_price,
        }


class PriceTable:
    """Validated, immutable price table with an explicit revision and currency."""

    __slots__ = ("revision", "currency", "entries", "entries_sha256")

    def __init__(self, revision: str, currency: str, entries: Sequence[PriceEntry]) -> None:
        self.revision = revision
        self.currency = currency
        self.entries = tuple(entries)
        canonical = json.dumps(
            {
                "schema": PRICE_TABLE_SCHEMA,
                "revision": revision,
                "currency": currency,
                "providers": [entry.as_dict() for entry in self.entries],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        self.entries_sha256 = hashlib.sha256(canonical).hexdigest()

    def lookup(self, provider_id: str | None, model_id: str | None) -> PriceEntry | None:
        if not isinstance(provider_id, str) or not isinstance(model_id, str):
            return None
        return next((row for row in self.entries if row.provider_id == provider_id and row.model_id == model_id), None)

    def identity(self) -> dict[str, str]:
        """Stable binding for resume checks and run identity."""
        return {
            "schema": PRICE_TABLE_SCHEMA,
            "revision": self.revision,
            "currency": self.currency,
            "sha256": self.entries_sha256,
        }

    def estimate(self, provider_id: str | None, model_id: str | None, usage: Any) -> dict[str, Any] | None:
        """Estimate observed usage, or ``None`` when it cannot be established."""
        entry = self.lookup(provider_id, model_id)
        tokens = usage_tokens(usage)
        if entry is None or tokens is None:
            return None
        input_tokens, output_tokens = tokens
        return {
            "microunits": _token_cost(entry.input_price, input_tokens) + _token_cost(entry.output_price, output_tokens),
            "known": True,
            "basis": PRICE_TABLE_BASIS,
            "currency": self.currency,
            "price_table_revision": self.revision,
        }

    def bound_call(
        self,
        provider_id: str | None,
        model_id: str | None,
        input_bytes: Any,
        max_output_tokens: Any = None,
        max_output_bytes: Any = None,
    ) -> dict[str, Any] | None:
        """Conservative ceiling for one call; input tokens never exceed UTF-8 bytes."""
        entry = self.lookup(provider_id, model_id)
        if entry is None or isinstance(input_bytes, bool) or not isinstance(input_bytes, int) or input_bytes < 0:
            return None
        output_cap: int | None = None
        if isinstance(max_output_tokens, int) and not isinstance(max_output_tokens, bool) and max_output_tokens >= 0:
            output_cap = max_output_tokens
        elif isinstance(max_output_bytes, int) and not isinstance(max_output_bytes, bool) and max_output_bytes >= 0:
            output_cap = max_output_bytes
        if output_cap is None:
            return None
        microunits = _token_cost(entry.input_price, input_bytes) + _token_cost(entry.output_price, output_cap)
        return {
            "max_cost_microunits": microunits,
            "estimated_cost_microunits": microunits,
            "reservation_kind": "price_table_bound",
            "basis": PRICE_TABLE_BASIS,
            "currency": self.currency,
            "price_table_revision": self.revision,
        }


def _valid_token(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def usage_tokens(usage: Any) -> tuple[int, int] | None:
    """Trusted input/output token counts; a total-only record is unknown."""
    if not isinstance(usage, Mapping):
        return None
    input_value = usage.get("prompt_tokens")
    if not _valid_token(input_value):
        input_value = usage.get("input_tokens")
    output_value = usage.get("completion_tokens")
    if not _valid_token(output_value):
        output_value = usage.get("output_tokens")
    if not _valid_token(input_value) or not _valid_token(output_value):
        return None
    return int(input_value), int(output_value)


def provider_price_identity(target: Any) -> tuple[str | None, str | None]:
    """Extract the configured provider/model pair used for an exact lookup."""
    identity = getattr(target, "identity", None)
    if callable(identity):
        identity = identity()
    provider_id = model_id = None
    if isinstance(identity, Mapping):
        provider_id = next(
            (identity[key] for key in ("provider_id", "kind") if isinstance(identity.get(key), str) and identity[key]),
            None,
        )
        model_id = next(
            (
                identity[key]
                for key in ("model_id", "model", "configured_model_id")
                if isinstance(identity.get(key), str) and identity[key]
            ),
            None,
        )
    if model_id is None:
        value = getattr(target, "model", None)
        model_id = value if isinstance(value, str) and value else None
    return provider_id, model_id


def validate_cost_ceiling(table: PriceTable | None, limits: Mapping[str, Any]) -> None:
    """Fail closed unless a numeric ceiling has an explicit matching currency."""
    if limits.get("max_cost_microunits") is None:
        return
    currency = limits.get("max_cost_currency")
    if not isinstance(currency, str) or not _CURRENCY.fullmatch(currency):
        raise PriceTableError("configured monetary budget requires max_cost_currency")
    if table is not None and table.currency != currency:
        raise PriceTableError("configured monetary budget currency does not match the price table")


def price_table_from_document(document: Any) -> PriceTable:
    """Validate a decoded JSON object as one versioned price table."""
    if not isinstance(document, Mapping) or set(document) != _TOP_LEVEL_FIELDS:
        raise PriceTableError("price table fields are invalid")
    if document.get("schema") != PRICE_TABLE_SCHEMA:
        raise PriceTableError("price table schema is unsupported")
    revision = document.get("revision")
    if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
        raise PriceTableError("price table revision is invalid")
    currency = document.get("currency")
    if not isinstance(currency, str) or not _CURRENCY.fullmatch(currency):
        raise PriceTableError("price table currency is invalid")
    providers = document.get("providers")
    if (
        not isinstance(providers, list)
        or not 1 <= len(providers) <= MAX_PRICE_TABLE_ENTRIES
        or any(not isinstance(entry, Mapping) for entry in providers)
    ):
        raise PriceTableError("price table providers are invalid")
    entries: list[PriceEntry] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(providers):
        if set(raw) != _ENTRY_FIELDS:
            raise PriceTableError("price table provider fields are invalid")
        provider_id = _bounded_text(raw.get("provider_id"), "provider_id")
        model_id = _bounded_text(raw.get("model_id"), "model_id")
        if (provider_id, model_id) in seen:
            raise PriceTableError("price table provider entries are duplicated")
        seen.add((provider_id, model_id))
        entries.append(
            PriceEntry(
                provider_id,
                model_id,
                _price(
                    raw.get("input_price_microunits_per_million_tokens"),
                    f"providers[{index}].input_price_microunits_per_million_tokens",
                ),
                _price(
                    raw.get("output_price_microunits_per_million_tokens"),
                    f"providers[{index}].output_price_microunits_per_million_tokens",
                ),
            )
        )
    return PriceTable(revision=revision, currency=currency, entries=entries)


def load_price_table(path: str | Path) -> PriceTable:
    """Read one bounded regular JSON file; never fetch or follow a URL."""
    location = Path(path)
    try:
        if location.stat().st_size > MAX_PRICE_TABLE_BYTES:
            raise PriceTableError("price table exceeds its size limit")
        raw = location.read_bytes()
    except OSError:
        raise PriceTableError("price table is unavailable") from None
    if len(raw) > MAX_PRICE_TABLE_BYTES:
        raise PriceTableError("price table exceeds its size limit")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError):
        raise PriceTableError("price table JSON is invalid") from None
    return price_table_from_document(document)
