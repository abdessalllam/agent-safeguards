"""Output rules shared by the screenshot extras: new PNG files only, with bounded pixels and bytes."""

from __future__ import annotations

import os
import shutil
import stat
import struct
import subprocess
import tempfile

from agent_safeguards.common import find_executable, message

MIN_SIDE = 100
MAX_SIDE = 1568
MAX_BYTES = 1024 * 1024
FLOOR_SIDE = 320
SHRINK_STEP = 0.8
SHRINK_TIMEOUT_SECONDS = 30
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SIPS = find_executable("sips")

# The files this run created, by path. A later write or cleanup checks that the path still names the same file, so a
# link or another file moved onto the path while a slow capture ran is never written through or deleted.
_CLAIMED: dict[str, tuple[int, int]] = {}


class ScreenshotError(Exception):
    """A failure whose text is already localized and ready to show."""


def png_size(path: str) -> tuple[int, int] | None:
    try:
        with open(path, "rb") as handle:
            header = handle.read(24)
    except OSError:
        return None
    if len(header) < 24 or header[:8] != PNG_SIGNATURE or header[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", header[16:24])
    return width, height


def _claim(path: str, descriptor: int) -> None:
    status = os.fstat(descriptor)
    _CLAIMED[path] = (status.st_dev, status.st_ino)


def _still_ours(path: str) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(status.st_mode) and _CLAIMED.get(path) == (status.st_dev, status.st_ino)


def discard(path: str | None) -> None:
    """Remove a file this run reserved, unless something else has taken its place."""
    if path is not None and _still_ours(path):
        try:
            os.remove(path)
        except OSError:
            pass
    if path is not None:
        _CLAIMED.pop(path, None)


def reserve_output(requested: str | None, prefix: str) -> str:
    # The commands can run without a prompt, so they only ever create new .png files. Creating the file with O_EXCL
    # claims the path atomically, which also means the cleanup on failure only ever removes a file this run made.
    if requested is None:
        handle, path = tempfile.mkstemp(prefix=prefix, suffix=".png")
        _claim(path, handle)
        os.close(handle)
        return path
    path = os.path.abspath(requested)
    if not path.lower().endswith(".png"):
        raise ScreenshotError(message("screenshot.error.not_png"))
    if not os.path.isdir(os.path.dirname(path)):
        raise ScreenshotError(message("screenshot.error.no_folder", path=os.path.dirname(path)))
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    except FileExistsError:
        raise ScreenshotError(message("screenshot.error.exists", path=path)) from None
    except OSError:
        raise ScreenshotError(message("screenshot.error.not_writable", path=path)) from None
    _claim(path, descriptor)
    os.close(descriptor)
    return path


def _write_at(source: str, destination: str, side: int, source_side: int) -> None:
    if side >= source_side:
        shutil.copyfile(source, destination)
        return
    if SIPS is None:
        raise ScreenshotError(message("screenshot.error.no_sips"))
    try:
        shrunk = subprocess.run([SIPS, "-Z", str(side), source, "--out", destination], capture_output=True, text=True, timeout=SHRINK_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        raise ScreenshotError(message("screenshot.error.shrink")) from None
    if shrunk.returncode != 0:
        raise ScreenshotError(message("screenshot.error.shrink"))


def _publish(source: str, destination: str) -> None:
    # The final write goes through the descriptor of a file whose identity is checked, never through the path alone.
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_NOFOLLOW)
    except OSError:
        raise ScreenshotError(message("screenshot.error.not_writable", path=destination)) from None
    with os.fdopen(descriptor, "wb") as writer:
        status = os.fstat(writer.fileno())
        if not stat.S_ISREG(status.st_mode) or _CLAIMED.get(destination) != (status.st_dev, status.st_ino):
            raise ScreenshotError(message("screenshot.error.exists", path=destination))
        os.ftruncate(writer.fileno(), 0)
        with open(source, "rb") as reader:
            shutil.copyfileobj(reader, writer)


def fit_png(source: str, destination: str, max_side: int, max_bytes: int = MAX_BYTES) -> None:
    """Write source to the reserved destination as a PNG whose longest side is at most max_side and whose size is at most max_bytes."""
    sides = png_size(source)
    if sides is None:
        raise ScreenshotError(message("screenshot.error.not_a_png"))
    source_side = max(sides)
    side = min(max_side, source_side)
    handle, work = tempfile.mkstemp(prefix="screenshot-fit-", suffix=".png")
    os.close(handle)
    try:
        while True:
            _write_at(source, work, side, source_side)
            written = png_size(work)
            if written is None or max(written) > max_side:
                raise ScreenshotError(message("screenshot.error.too_big", pixels=max_side, kilobytes=max_bytes // 1024))
            if os.path.getsize(work) <= max_bytes:
                _publish(work, destination)
                return
            side = int(max(written) * SHRINK_STEP)
            if side < FLOOR_SIDE:
                raise ScreenshotError(message("screenshot.error.too_big", pixels=max_side, kilobytes=max_bytes // 1024))
    finally:
        try:
            os.remove(work)
        except OSError:
            pass
