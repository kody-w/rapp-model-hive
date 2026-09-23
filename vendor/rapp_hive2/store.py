"""Carriers: portable, content-addressed folders (one behavior on macOS, Linux and Windows).

A carrier is transport, never identity. Paths obey the strictest common rules
(NFC, no reserved names, no case collisions, short enough for Windows); reads
never leave the chosen folder or follow links; writes create files exclusively
and never overwrite. OS choices never enter content hashes.
"""

from __future__ import annotations

import errno
import os
import platform
import stat
import sys
import tempfile
import time
import unicodedata
from pathlib import Path
from typing import Any

from .rapp1 import Refusal

WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
)
INVALID_CHARS = frozenset('<>:"\\|?*')
MAX_COMPONENT_BYTES = 255
MAX_RELATIVE_PATH = 180  # leaves room under Windows MAX_PATH (260) for a worktree prefix


def platform_profile() -> dict[str, Any]:
    windows = os.name == "nt" or sys.platform.startswith(("win", "cygwin", "msys"))
    return {
        "os_family": "windows" if windows else "posix",
        "system": platform.system() or "unknown",
        "python": platform.python_version(),
        "posix_no_follow": all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY")),
        "path_rules": "portable-strictest-common-subset",
    }


def portable_path(value: object) -> str:
    """Validate a relative POSIX path that is safe on macOS, Linux and Windows."""
    if type(value) is not str or not value or value.startswith("/") or len(value) > MAX_RELATIVE_PATH:
        raise Refusal("REFUSE_PORTABLE_PATH", "A bounded relative POSIX path is required.")
    if unicodedata.normalize("NFC", value) != value:
        raise Refusal("REFUSE_PORTABLE_PATH", "Paths must already be Unicode NFC (macOS NFD differs).")
    for part in value.split("/"):
        stem = part.split(".", 1)[0].upper()
        if (
            part in ("", ".", "..")
            or len(part.encode("utf-8")) > MAX_COMPONENT_BYTES
            or any(char in INVALID_CHARS or ord(char) < 32 or ord(char) == 127 for char in part)
            or part.endswith((".", " "))
            or stem in WINDOWS_RESERVED
        ):
            raise Refusal("REFUSE_PORTABLE_PATH", f"Path component is not portable to every OS: {part!r}")
    return value


def portable_collisions(paths: list[str]) -> list[list[str]]:
    """Paths that would collide on case-insensitive or normalizing filesystems."""
    seen: dict[str, list[str]] = {}
    for path in paths:
        seen.setdefault(unicodedata.normalize("NFC", path).casefold(), []).append(path)
    return [sorted(group) for group in seen.values() if len(group) > 1]


def atomic_write(path: Path, data: bytes, *, attempts: int = 6) -> None:
    """Write-then-rename in the same directory; retries transient Windows sharing locks."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".hive2-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        for attempt in range(attempts):
            try:
                os.replace(temporary, path)
                return
            except PermissionError:
                if attempt == attempts - 1:
                    raise
                time.sleep(0.05 * 2**attempt)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


_BINARY = getattr(os, "O_BINARY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def pinned_directories() -> bool:
    """POSIX: walk directories by handle with no-follow opens (immune to link swaps)."""
    return (
        hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.open in os.supports_dir_fd
        and os.mkdir in os.supports_dir_fd
        and os.listdir in os.supports_fd
    )


def is_link(info: os.stat_result) -> bool:
    """Symlinks, and on Windows junctions and every other reparse point."""
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _read_descriptor(descriptor: int, name: str, limit: int) -> bytes:
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise Refusal("REFUSE_UNSAFE_PATH", f"{name} is not a plain file.")
        if info.st_size > limit:
            raise Refusal("REFUSE_JSON_SIZE", f"{name} is larger than its bound.")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise Refusal("REFUSE_JSON_SIZE", f"{name} is larger than its bound.")
    return data


def read_bounded(path: Path, *, limit: int) -> bytes:
    """Read a file a person chose: plain files only (no FIFOs or devices), never more than ``limit``."""
    try:
        descriptor = os.open(path, os.O_RDONLY | _NONBLOCK | _BINARY)
    except FileNotFoundError as exc:
        raise Refusal("REFUSE_NOT_FOUND", f"There is no file named {Path(path).name}.") from exc
    except OSError as exc:
        raise Refusal("REFUSE_IO", f"{Path(path).name} cannot be opened ({exc.strerror}).") from exc
    return _read_descriptor(descriptor, Path(path).name, limit)


def read_inside(root: Path, relative: str, *, limit: int) -> bytes:
    """Read one file strictly inside ``root``: portable relative path, no links anywhere below root."""
    parts = portable_path(relative).split("/")
    try:
        if pinned_directories():
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    os.close(directory)
                    directory = child
                descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | _NONBLOCK, dir_fd=directory)
            finally:
                os.close(directory)
        else:
            current = Path(root)
            for part in parts:
                current = current / part
                if is_link(os.lstat(current)):
                    raise Refusal("REFUSE_UNSAFE_PATH", f"{relative} passes through a link.")
            descriptor = os.open(current, os.O_RDONLY | _BINARY)
    except FileNotFoundError as exc:
        raise Refusal("REFUSE_FOLDER_INCOMPLETE", f"{relative} is missing from the folder.") from exc
    except OSError as exc:
        raise Refusal("REFUSE_UNSAFE_PATH", f"{relative} is a link or not a plain file.") from exc
    return _read_descriptor(descriptor, relative, limit)


def _write_descriptor(descriptor: int, data: bytes) -> None:
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def write_new_tree(root: Path, files: dict[str, bytes], *, last: str | None = None, require_empty: bool = True) -> None:
    """Create every file exclusively inside a new or empty folder: never overwrite, never follow a link.

    ``last`` is written after everything else, so its presence marks a complete copy.
    """
    order = sorted(path for path in files if path != last) + ([last] if last in files else [])
    for path in order:
        portable_path(path)
    root = Path(root)
    root.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mkdir(root, 0o700)
    except FileExistsError:
        pass
    info = os.lstat(root)
    if is_link(info) or not stat.S_ISDIR(info.st_mode):
        raise Refusal("REFUSE_CONFLICT", "The destination is a link or a file; carry into a new or empty folder.")
    identity = (info.st_dev, info.st_ino)
    try:
        if pinned_directories():
            _write_tree_pinned(root, files, order, identity, require_empty)
        else:
            _write_tree_checked(root, files, order, identity, require_empty)
    except FileExistsError as exc:
        raise Refusal("REFUSE_CONFLICT", "A file already exists in the destination; nothing was overwritten.") from exc
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
            raise Refusal("REFUSE_UNSAFE_PATH", "Part of the destination is a link; nothing was followed.") from exc
        raise Refusal("REFUSE_IO", f"The copy could not be written ({exc.strerror}).") from exc


def _write_tree_pinned(root: Path, files: dict[str, bytes], order: list[str], identity: tuple[int, int], require_empty: bool = True) -> None:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    opened = {"": root_fd}
    try:
        pinned = os.fstat(root_fd)
        if (pinned.st_dev, pinned.st_ino) != identity:
            raise Refusal("REFUSE_UNSAFE_PATH", "The destination folder was replaced while the copy was starting; nothing was written.")
        if require_empty and os.listdir(root_fd):
            raise Refusal("REFUSE_CONFLICT", "Carry into a new or empty folder; existing files are never overwritten.")
        for path in order:
            parts = path.split("/")
            directory, prefix = root_fd, ""
            for part in parts[:-1]:
                prefix += part + "/"
                if prefix not in opened:
                    try:
                        os.mkdir(part, 0o700, dir_fd=directory)
                    except FileExistsError:
                        pass
                    opened[prefix] = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                directory = opened[prefix]
            descriptor = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            _write_descriptor(descriptor, files[path])
    finally:
        for descriptor in opened.values():
            os.close(descriptor)


def _same_root(root: Path, identity: tuple[int, int]) -> None:
    info = os.lstat(root)
    if is_link(info) or not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
        raise Refusal("REFUSE_UNSAFE_PATH", "The destination folder was replaced during the copy; stopped without overwriting anything.")


def _write_tree_checked(root: Path, files: dict[str, bytes], order: list[str], identity: tuple[int, int], require_empty: bool = True) -> None:
    """Hosts without directory handles (Windows): exclusive creates, link checks on every folder, and the
    destination's identity re-checked before every write (the best available without handles; still never overwrites)."""
    _same_root(root, identity)
    with os.scandir(root) as entries:
        if require_empty and any(True for _ in entries):
            raise Refusal("REFUSE_CONFLICT", "Carry into a new or empty folder; existing files are never overwritten.")
    for path in order:
        _same_root(root, identity)
        parts = path.split("/")
        current = root
        for part in parts[:-1]:
            current = current / part
            try:
                os.mkdir(current, 0o700)
            except FileExistsError:
                pass
            info = os.lstat(current)
            if is_link(info) or not stat.S_ISDIR(info.st_mode):
                raise Refusal("REFUSE_UNSAFE_PATH", "Part of the destination is a link; nothing was followed.")
        descriptor = os.open(current / parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY, 0o600)
        _write_descriptor(descriptor, files[path])
