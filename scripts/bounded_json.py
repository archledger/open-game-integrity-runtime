"""Consumer-neutral bounded JSON admission for repository test fixtures."""

from __future__ import annotations

import json
import math
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


_RECURSION_CONTEXTS = {
    "maximum recursion depth exceeded": "generic",
    "maximum recursion depth exceeded while decoding a JSON array from a unicode string": "array",
    "maximum recursion depth exceeded while decoding a JSON object from a unicode string": "object",
}


@dataclass(frozen=True)
class JsonLimits:
    bytes: int
    depth: int
    object_fields: int
    array_items: int
    string_characters: int
    object_key_characters: int
    number_token_characters: int
    total_nodes: int
    root_depth: int = 1

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> JsonLimits:
        return cls(
            **{
                field: values[field]
                for field in cls.__dataclass_fields__
                if field != "root_depth"
            }
        )


@dataclass(frozen=True)
class StableFileIdentity:
    device: int
    inode: int
    mode: int
    link_count: int
    owner: int
    group: int
    size: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def from_stat(cls, value: Any) -> StableFileIdentity:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=value.st_mode,
            link_count=value.st_nlink,
            owner=value.st_uid,
            group=value.st_gid,
            size=value.st_size,
            modified_ns=value.st_mtime_ns,
            changed_ns=value.st_ctime_ns,
        )


class BoundedJsonError(ValueError):
    def __init__(
        self,
        diagnostic: str,
        category: str = "invalid",
        line: int | None = None,
        column: int | None = None,
        context: str | None = None,
    ) -> None:
        super().__init__(diagnostic)
        self.category = category
        self.line = line
        self.column = column
        self.context = context


class _JsonFailure(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


def _unique_object(
    pairs: list[tuple[str, Any]], maximum_fields: int | None = None
) -> dict[str, Any]:
    if maximum_fields is not None and len(pairs) > maximum_fields:
        raise _JsonFailure("object-fields")
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _JsonFailure("duplicate")
        result[key] = value
    return result


def _reject_constant(_token: str) -> Any:
    raise _JsonFailure("non-json-constant")


def _bounded_float(token: str, maximum: int) -> float:
    if len(token) > maximum:
        raise _JsonFailure("number-token")
    value = float(token)
    if not math.isfinite(value):
        raise _JsonFailure("finite-range")
    return value


def _bounded_int(token: str, maximum: int) -> int:
    if len(token) > maximum:
        raise _JsonFailure("integer-token")
    return int(token)


class _VisitorFailure(BaseException):
    def __init__(self, error):
        super().__init__()
        self.error = error


def _check_tree(
    value: Any,
    limits: JsonLimits,
    depth: int = 1,
    nodes: list[int] | None = None,
    node_visit: Callable[[], None] | None = None,
) -> None:
    if node_visit is not None:
        try:
            node_visit()
        except Exception as error:
            raise _VisitorFailure(error) from None
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > limits.total_nodes:
        raise _JsonFailure("total-nodes")
    if depth > limits.depth:
        raise _JsonFailure("depth")
    if isinstance(value, dict):
        if len(value) > limits.object_fields:
            raise _JsonFailure("object-fields")
        if any(len(key) > limits.object_key_characters for key in value):
            raise _JsonFailure("object-key")
        for child in value.values():
            _check_tree(child, limits, depth + 1, nodes, node_visit)
    elif isinstance(value, list):
        if len(value) > limits.array_items:
            raise _JsonFailure("array-items")
        for child in value:
            _check_tree(child, limits, depth + 1, nodes, node_visit)
    elif isinstance(value, str) and len(value) > limits.string_characters:
        raise _JsonFailure("string")


def render_bounded_json_error(diagnostic: str, _error: BaseException) -> str:
    return diagnostic


def _read_file(
    approved_root: Path,
    relative_path: str,
    maximum: int,
    expected_hierarchy: tuple[StableFileIdentity, ...] | None = None,
    expected_file_identity: StableFileIdentity | None = None,
) -> tuple[bytes, StableFileIdentity]:
    parts = relative_path.split("/")
    if not relative_path or relative_path.startswith("/") or any(
        part in {"", ".", ".."} for part in parts
    ):
        raise _JsonFailure("io")
    root_fd = os.open(
        approved_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    directory_fds = [root_fd]
    try:
        if expected_hierarchy is not None:
            if len(expected_hierarchy) != len(parts):
                raise _JsonFailure("identity")
            root_identity = StableFileIdentity.from_stat(os.fstat(root_fd))
            if root_identity != expected_hierarchy[0]:
                raise _JsonFailure("identity")
        for index, part in enumerate(parts[:-1], start=1):
            directory_fds.append(
                os.open(
                    part,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    dir_fd=directory_fds[-1],
                )
            )
            if expected_hierarchy is not None:
                directory_identity = StableFileIdentity.from_stat(
                    os.fstat(directory_fds[-1])
                )
                if directory_identity != expected_hierarchy[index]:
                    raise _JsonFailure("identity")
        file_fd = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fds[-1],
        )
        try:
            before = os.fstat(file_fd)
            before_identity = StableFileIdentity.from_stat(before)
            if not stat.S_ISREG(before.st_mode):
                raise _JsonFailure("io")
            if (
                expected_file_identity is not None
                and before_identity != expected_file_identity
            ):
                raise _JsonFailure("identity")
            if before.st_size > maximum:
                raise _JsonFailure("bytes")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining and (
                chunk := os.read(file_fd, min(65536, remaining))
            ):
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(file_fd)
            after_identity = StableFileIdentity.from_stat(after)
            if len(raw) > maximum:
                raise _JsonFailure("bytes")
            if (
                not stat.S_ISREG(after.st_mode)
                or before_identity != after_identity
                or len(raw) != after.st_size
            ):
                raise _JsonFailure("io")
            if expected_hierarchy is not None:
                for directory_fd, expected_identity in zip(
                    directory_fds, expected_hierarchy, strict=True
                ):
                    current_identity = StableFileIdentity.from_stat(
                        os.fstat(directory_fd)
                    )
                    if current_identity != expected_identity:
                        raise _JsonFailure("identity")
            return raw, before_identity
        finally:
            os.close(file_fd)
    finally:
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)


def read_bounded_bytes(
    approved_root: Path,
    relative_path: str,
    maximum: int,
    diagnostic: str,
) -> bytes:
    """Return stable bounded regular-file bytes without parsing or callbacks.

    Directory components and the final file are opened without following links.
    This consumer-neutral seam conveys no decoded values or semantic results.
    """
    try:
        raw, _identity = _read_file(approved_root, relative_path, maximum)
        return raw
    except _JsonFailure as error:
        raise BoundedJsonError(diagnostic, error.category) from None
    except OSError:
        raise BoundedJsonError(diagnostic, "io") from None


def load_bounded_json(
    approved_root: Path,
    relative_path: str,
    limits: JsonLimits,
    diagnostic: str,
    *,
    node_visit: Callable[[], None] | None = None,
) -> Any:
    value, _identity = load_bounded_json_with_identity(
        approved_root, relative_path, limits, diagnostic, node_visit=node_visit
    )
    return value


def load_bounded_json_with_identity(
    approved_root: Path,
    relative_path: str,
    limits: JsonLimits,
    diagnostic: str,
    *,
    node_visit: Callable[[], None] | None = None,
) -> tuple[Any, StableFileIdentity]:
    return _load_bounded_json_document(
        approved_root, relative_path, limits, diagnostic, node_visit=node_visit
    )


def load_exact_bounded_json(
    approved_root: Path,
    relative_path: str,
    limits: JsonLimits,
    diagnostic: str,
    expected_bytes: bytes,
    *,
    node_visit: Callable[[], None] | None = None,
) -> Any:
    """Admit one document only when its stable bytes match a trusted recipe."""
    value, _identity = _load_bounded_json_document(
        approved_root,
        relative_path,
        limits,
        diagnostic,
        expected_bytes,
        node_visit=node_visit,
    )
    return value


def load_bounded_json_matching_identity(
    approved_root: Path,
    relative_path: str,
    limits: JsonLimits,
    diagnostic: str,
    expected_identity: StableFileIdentity,
    expected_bytes: bytes | None = None,
    expected_hierarchy: tuple[StableFileIdentity, ...] | None = None,
    *,
    node_visit: Callable[[], None] | None = None,
) -> Any:
    """Admit one document only while its layer-1 hierarchy remains stable."""
    value, _identity = _load_bounded_json_document(
        approved_root,
        relative_path,
        limits,
        diagnostic,
        expected_bytes,
        expected_identity,
        expected_hierarchy,
        node_visit=node_visit,
    )
    return value


def _load_bounded_json_document(
    approved_root: Path,
    relative_path: str,
    limits: JsonLimits,
    diagnostic: str,
    expected_bytes: bytes | None = None,
    expected_identity: StableFileIdentity | None = None,
    expected_hierarchy: tuple[StableFileIdentity, ...] | None = None,
    *,
    node_visit: Callable[[], None] | None = None,
) -> tuple[Any, StableFileIdentity]:
    try:
        raw, identity = _read_file(
            approved_root,
            relative_path,
            limits.bytes,
            expected_hierarchy,
            expected_identity,
        )
        if expected_bytes is not None and raw != expected_bytes:
            raise _JsonFailure("content")
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=lambda pairs: _unique_object(
                pairs, limits.object_fields
            ),
            parse_constant=_reject_constant,
            parse_float=lambda token: _bounded_float(
                token, limits.number_token_characters
            ),
            parse_int=lambda token: _bounded_int(token, limits.number_token_characters),
        )
        _check_tree(value, limits, limits.root_depth, node_visit=node_visit)
        return value, identity
    except _VisitorFailure as failure:
        raise failure.error from None
    except UnicodeDecodeError:
        raise BoundedJsonError(diagnostic, "utf8") from None
    except json.JSONDecodeError as error:
        raise BoundedJsonError(
            diagnostic, "malformed", error.lineno, error.colno
        ) from None
    except _JsonFailure as error:
        category = (
            "identity"
            if expected_hierarchy is not None and error.category == "io"
            else error.category
        )
        raise BoundedJsonError(diagnostic, category) from None
    except OSError:
        category = "identity" if expected_hierarchy is not None else "io"
        raise BoundedJsonError(diagnostic, category) from None
    except RecursionError as error:
        detail = (
            error.args[0]
            if len(error.args) == 1 and isinstance(error.args[0], str)
            else ""
        )
        context = _RECURSION_CONTEXTS.get(detail, "unknown")
        raise BoundedJsonError(
            diagnostic, "recursion", context=context
        ) from None
    except (OverflowError, ValueError):
        raise BoundedJsonError(diagnostic, "invalid-number") from None
