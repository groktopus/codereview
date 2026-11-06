"""Typed taxonomy for expected boundary failures and harness defects.

The harness has many deliberate fail-closed handlers: a transport, credential,
budget, or untrusted-payload boundary failed and the only safe outcome is an
explicit *unknown*, *stale*, *rejected*, or *incomplete* result.  Those are
expected operational failures and are represented by :class:`ExpectedBoundaryError`
subclasses.

A programming error in harness-owned code (for example ``TypeError`` from an
assessor implementation or ``AttributeError`` from a parser) is *not* an
expected boundary failure.  It must never be silently downgraded to a benign
or UNKNOWN result.  The helpers below let audited handlers separate the two
cases explicitly, and let stage code record a defect instead of pretending a
normal failure occurred.

This module intentionally has no imports from other harness modules so every
error class can depend on it without import cycles.
"""

from __future__ import annotations


class HarnessError(Exception):
    """Base class for errors the harness raises deliberately."""


class ExpectedBoundaryError(HarnessError):
    """An expected failure at a boundary; callers must fail closed.

    Subclasses also inherit the historical builtin base class (``ValueError``,
    ``RuntimeError``, ``TimeoutError``) so existing handlers and tests keep
    their backward-compatible ``except`` semantics and messages/codes.
    """


class BoundaryValueError(ExpectedBoundaryError, ValueError):
    """An expected boundary failure whose historical type was ``ValueError``."""


class BoundaryRuntimeError(ExpectedBoundaryError, RuntimeError):
    """An expected boundary failure whose historical type was ``RuntimeError``."""


class BoundaryTimeoutError(ExpectedBoundaryError, TimeoutError):
    """An expected boundary failure whose historical type was ``TimeoutError``."""


class DefectError(HarnessError, AssertionError):
    """A programming error in harness-owned code, surfaced deliberately.

    Raised only after the caller has restored enough state for an auditable
    failure record; it is never converted into a normal review outcome.
    """


# Exception types that always mean harness-owned code is wrong. ``TypeError``
# is deliberately included: the audited inspect/validate paths catch expected
# shape errors explicitly and must let a type error escape instead.
_DEFECT_TYPES: tuple[type[BaseException], ...] = (
    DefectError,
    TypeError,
    AttributeError,
    NameError,
    UnboundLocalError,
    NotImplementedError,
    ImportError,
    AssertionError,
)

_DEFECT_NAMES = frozenset(kind.__name__ for kind in _DEFECT_TYPES)


def is_defect(exc: BaseException | str | type | None) -> bool:
    """Return true when *exc* is a programming defect, not a boundary failure.

    ``exc`` may be an exception instance, an exception class, or the
    ``remote_type`` name recorded by :class:`IsolatedCallError` for an
    exception raised inside a spawned worker.  Boundary failures wrapped by a
    worker (``ProviderError``, ``ValueError``, timeouts) are not defects.
    """
    if exc is None:
        return False
    remote_type = getattr(exc, "remote_type", None)
    if isinstance(remote_type, str) and remote_type in _DEFECT_NAMES:
        return True
    if isinstance(exc, str):
        return exc in _DEFECT_NAMES
    if isinstance(exc, type):
        return issubclass(exc, _DEFECT_TYPES)
    return isinstance(exc, _DEFECT_TYPES)


def classify_exception(exc: BaseException | str | type | None) -> str:
    """Classify *exc* as ``"defect"``, ``"boundary"``, or ``"unexpected"``.

    ``"unexpected"`` is any other exception; audited fail-closed handlers that
    keep a broad ``except Exception`` must decide explicitly whether such an
    exception is safe to downgrade and record that rationale in
    ``docs/EXCEPTION-AUDIT.md``.
    """
    if is_defect(exc):
        return "defect"
    if isinstance(exc, ExpectedBoundaryError):
        return "boundary"
    if isinstance(exc, type) and issubclass(exc, ExpectedBoundaryError):
        return "boundary"
    return "unexpected"


def defect_name(exc: BaseException | str | None) -> str | None:
    """Return the bounded type name for a defect, or ``None``."""
    if not is_defect(exc):
        return None
    remote_type = getattr(exc, "remote_type", None)
    if isinstance(remote_type, str) and remote_type in _DEFECT_NAMES:
        return remote_type
    if isinstance(exc, str):
        return exc if exc in _DEFECT_NAMES else None
    return type(exc).__name__ if exc is not None else None
