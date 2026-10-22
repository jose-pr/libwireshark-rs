"""A capture file format written as classes: Wireshark (4.6 on) opens files
in it with `-r`.

```python
class PygCapReader(CaptureReader):
    def read(self, file: CaptureFile) -> Optional[Record]:
        header = file.read_exact(16)
        if header is None:
            return None
        time, captured, original = struct.unpack("<QII", header)
        return Record(file.read_exact(captured) or b"", time_ns=time, original_len=original)


class PygCap(provide.Provider, FileType):
    NAME = "pygcap"
    DESCRIPTION = "PYGCAP example capture"
    EXTENSIONS = ["pygcap"]

    def reader(self, file: CaptureFile) -> Optional[CaptureReader]:
        return PygCapReader() if file.read(8) == MAGIC else None
```
"""

from __future__ import annotations

__all__ = ["CaptureFile", "CaptureReader", "FileType", "Record"]

from dataclasses import dataclass
from typing import Any, ClassVar, Dict, Optional, Sequence

from guatiao import NotFound

from . import kinds
from ._engine import Encapsulation


class CaptureFile:
    """The file being read, lent for one call: reads go through Wireshark,
    which undoes compression."""

    def __init__(self, source: Any) -> None:
        self._source = source

    def read(self, size: int) -> bytes:
        """Up to `size` bytes; fewer at the end of the file.

        Raises `OSError` when Wireshark cannot read the file.
        """
        buffer = bytearray(size)
        read = self._source.read(buffer)
        if read < 0:
            raise OSError("the capture file could not be read")
        return bytes(buffer[:read])

    def read_exact(self, size: int) -> Optional[bytes]:
        """Exactly `size` bytes, `None` at a clean end of the file.

        Raises `EOFError` when the file ends inside them.
        """
        data = b""
        while len(data) < size:
            chunk = self.read(size - len(data))
            if not chunk:
                if not data:
                    return None
                raise EOFError(f"{size - len(data)} bytes short")
            data += chunk
        return data

    @property
    def position(self) -> int:
        """The offset in the file."""
        return int(self._source.position())


@dataclass(frozen=True)
class Record:
    """One record of a capture."""

    data: bytes
    "The captured bytes."
    time_ns: Optional[int] = None
    "When it was captured, in nanoseconds since the Unix epoch."
    original_len: Optional[int] = None
    "Its length on the wire, when more was sent than captured."


class CaptureReader:
    """An open file's reader. Wireshark reads from one thread, one record at
    a time; for a second pass it repositions the file at a record's start."""

    ENCAPSULATION: ClassVar[int] = Encapsulation.ETHERNET
    "The link-layer type of every record (`WTAP_ENCAP_*`)."

    def read(self, file: CaptureFile) -> Optional[Record]:
        """The record at the file's position, `None` at the end."""
        raise NotImplementedError


class _Reading:
    """A `CaptureReader` as the `wireshark_capture_reader` object the host owns."""

    def __init__(self, reader: CaptureReader) -> None:
        self.reader = reader

    def encapsulation(self) -> int:
        return int(self.reader.ENCAPSULATION)

    def read(self, file: Any) -> Dict[str, Any]:
        record = self.reader.read(CaptureFile(file))
        if record is None:
            return {}
        answer: Dict[str, Any] = {"data": bytes(record.data)}
        if record.time_ns is not None:
            answer["time_ns"] = int(record.time_ns)
        if record.original_len is not None:
            answer["original_len"] = int(record.original_len)
        return answer


class FileType(kinds.FileType):
    """A capture file format: subclass it beside guatiao's `provide.Provider`.

    `NAME` is its short name (`[a-z][a-z0-9_]*`, as `tshark -F` lists it),
    `DESCRIPTION` its name for people, `EXTENSIONS` its files' extensions.
    `reader` gets each file Wireshark opens, at its start, and answers a
    `CaptureReader` for one in this format, `None` for another.
    """

    NAME: ClassVar[str]
    DESCRIPTION: ClassVar[str]
    EXTENSIONS: ClassVar[Sequence[str]] = ()

    def reader(self, file: CaptureFile) -> Optional[CaptureReader]:
        raise NotImplementedError

    def describe(self) -> Dict[str, Any]:
        cls = type(self)
        return {
            "name": cls.NAME,
            "description": cls.DESCRIPTION,
            "extensions": list(cls.EXTENSIONS),
        }

    def open(self, file: Any) -> _Reading:  # type: ignore[override]
        try:
            reader = self.reader(CaptureFile(file))
        except EOFError:
            reader = None
        if reader is None:
            raise NotFound(f"not {type(self).NAME}")
        return _Reading(reader)
