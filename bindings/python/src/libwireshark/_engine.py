"""Wireshark's dissection engine, run in this process through the
libwireshark-engine library: dissect frames and read capture files with
Wireshark's dissectors and the plugins you load."""

from __future__ import annotations

__all__ = ["Dissected", "Encapsulation", "Engine", "Node"]

import os
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple, Union

from guatiao import GuatiaoError

from . import kinds
from .exceptions import DisplayFilterError, EngineError

#: The engine library's path, when `Engine` is not given `library=`.
ENGINE_VARIABLE = "LIBWIRESHARK_ENGINE"

PathLike = Union[str, "os.PathLike[str]"]


class Encapsulation(IntEnum):
    """A frame's link-layer type, Wireshark's `WTAP_ENCAP_*`; any other
    value of it may be passed as an `int`."""

    ETHERNET = 1
    RAW_IP = 7


@dataclass(frozen=True)
class Node:
    """One item of the protocol tree."""

    abbrev: str
    "The field's filter name, such as `ip.src`; empty for a text item."
    name: str
    "The field's name, such as `Source Address`."
    label: str
    "The line the tree shows."
    value: Optional[str]
    "The value as Wireshark displays it; `None` for protocols and text."
    offset: int
    "Where the item starts in its data, in bytes."
    length: int
    "How many bytes it covers."
    hidden: bool = False
    "Present for filtering, not shown."
    generated: bool = False
    "Computed by a dissector, not read from the frame."
    children: Tuple["Node", ...] = ()
    "The items below it."

    @classmethod
    def from_map(cls, node: Mapping[str, Any]) -> "Node":
        return cls(
            abbrev=node.get("abbrev", ""),
            name=node.get("name", ""),
            label=node.get("label", ""),
            value=node.get("value"),
            offset=node.get("offset", -1),
            length=node.get("length", 0),
            hidden=bool(node.get("hidden", False)),
            generated=bool(node.get("generated", False)),
            children=tuple(cls.from_map(child) for child in node.get("children", ())),
        )


def _walk(nodes: Iterable[Node]) -> Iterator[Node]:
    for node in nodes:
        yield node
        yield from _walk(node.children)


@dataclass(frozen=True, eq=False)
class Dissected:
    """One dissected frame: its number, the packet list's columns and the
    protocol tree.

    `dissected["foo.version"]` is the first such field's value (`KeyError`
    when there is none), `get` the first node, `all` every one, depth first.
    """

    frame: int
    "Counted from 1 in the session, or in the file being read."
    columns: Dict[str, str] = field(default_factory=dict)
    "Each column's text by its title, in Wireshark's order."
    tree: Tuple[Node, ...] = ()
    "One node per protocol, each holding its fields."

    @classmethod
    def from_map(cls, frame: Mapping[str, Any]) -> "Dissected":
        return cls(
            frame=frame["frame"],
            columns={column["title"]: column["text"] for column in frame.get("columns", ())},
            tree=tuple(Node.from_map(node) for node in frame.get("tree", ())),
        )

    def all(self, abbrev: str) -> Iterator[Node]:
        return (node for node in _walk(self.tree) if node.abbrev == abbrev)

    def get(self, abbrev: str) -> Optional[Node]:
        return next(self.all(abbrev), None)

    def __contains__(self, abbrev: object) -> bool:
        return isinstance(abbrev, str) and self.get(abbrev) is not None

    def __getitem__(self, abbrev: str) -> Optional[str]:
        node = self.get(abbrev)
        if node is None:
            raise KeyError(abbrev)
        return node.value


# Wireshark's state is the process's and lives in the engine library, so
# the library, once loaded, stays loaded: the registry is never closed.
_lock = threading.Lock()
_registry: Optional[Any] = None
_engine: Optional[Any] = None
_engine_path: Optional[str] = None
_open: Optional["Engine"] = None


def _refused(error: GuatiaoError) -> EngineError:
    message = str(error)
    if "display filter:" in message:
        return DisplayFilterError(message)
    return EngineError(message)


def _bind(library: Optional[PathLike]) -> Any:
    """The engine library's `wireshark_engine` provider, loaded once."""
    global _registry, _engine, _engine_path
    path = os.fspath(library) if library is not None else os.environ.get(ENGINE_VARIABLE)
    if _engine is not None:
        if path is not None and os.path.abspath(path) != _engine_path:
            raise EngineError(f"the engine library is already loaded from {_engine_path}")
        return _engine
    if not path:
        raise EngineError(f"no engine library: pass library= or set {ENGINE_VARIABLE}")
    from guatiao.registry import Registry

    from . import __version__

    registry = Registry("libwireshark", __version__)
    try:
        registry.load_file(path)
        offers = registry.providers(kinds.Engine.kind.name)
        if not offers:
            raise EngineError(f"{path} provides no {kinds.Engine.kind.name}")
        _engine = registry.bind(offers[0]["key"], kinds.Engine)
    except GuatiaoError as error:
        raise EngineError(f"{path}: {error}") from error
    _registry, _engine_path = registry, os.path.abspath(path)
    return _engine


def _nanoseconds(time: Union[None, int, float, datetime]) -> int:
    if time is None:
        return 0
    seconds = time.timestamp() if isinstance(time, datetime) else time
    if seconds < 0:
        raise ValueError(f"a capture time before the Unix epoch: {time!r}")
    return round(seconds * 1_000_000_000)


class Engine:
    """Wireshark's dissection engine, started in this process.

    ```python
    with Engine(plugins=["foo.dll"], preferences={"foo.port": 113}) as wireshark:
        frame = wireshark.dissect(data)
        frame["foo.version"]
        for frame in wireshark.read("capture.pcapng", display_filter="foo"):
            print(frame.frame, frame.columns["Info"])
    ```

    `plugins` are Wireshark plugin libraries built for the running
    Wireshark's release line (dissectors, file types; the
    libwireshark-guatiao host among them), loaded besides the installed
    ones unless `skip_installed_plugins`. Preferences come from the profile
    in `config_dir` (the user's by default), with `preferences` set on top
    as `tshark -o name:value` sets them.

    Wireshark starts once per process, with the first engine's settings: a
    later `Engine` must give the same ones, and one may be open at a time.
    The engine library is `library`, else `LIBWIRESHARK_ENGINE`.
    """

    def __init__(
        self,
        plugins: Iterable[PathLike] = (),
        *,
        preferences: Optional[Mapping[str, object]] = None,
        config_dir: Optional[PathLike] = None,
        skip_installed_plugins: bool = False,
        library: Optional[PathLike] = None,
    ) -> None:
        global _open
        self._plugins: List[str] = [os.path.abspath(os.fspath(plugin)) for plugin in plugins]
        config: Dict[str, Any] = {
            "plugins": self._plugins,
            "skip_installed_plugins": skip_installed_plugins,
            "preferences": {name: _preference(value) for name, value in (preferences or {}).items()},
        }
        if config_dir is not None:
            config["config_dir"] = os.fspath(config_dir)
        self._calls = threading.Lock()
        with _lock:
            if _open is not None:
                raise EngineError(f"an engine is already open in this process: {_open!r}")
            engine = _bind(library)
            try:
                self._session: Optional[Any] = engine.open(config)
            except GuatiaoError as error:
                raise _refused(error) from error
            _open = self

    def __repr__(self) -> str:
        state = "open" if self._session is not None else "closed"
        return f"<Engine plugins={self._plugins!r} {state}>"

    def __enter__(self) -> "Engine":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _live(self) -> Any:
        if self._session is None:
            raise ValueError("the engine is closed")
        return self._session

    def dissect(
        self,
        data: bytes,
        encapsulation: int = Encapsulation.ETHERNET,
        time: Union[None, int, float, datetime] = None,
    ) -> Dissected:
        """Dissects one frame captured at `time` (seconds since the Unix
        epoch, or a `datetime`; the epoch when `None`). Frames dissected one
        after the other share conversations, as in one capture."""
        nanoseconds = _nanoseconds(time)
        with self._calls:
            try:
                answer = self._live().dissect(bytes(data), int(encapsulation), nanoseconds)
            except GuatiaoError as error:
                raise _refused(error) from error
        try:
            return Dissected.from_map(answer.to_python())
        finally:
            answer.close()

    def read(self, path: PathLike, display_filter: Optional[str] = None) -> Iterator[Dissected]:
        """The frames of the capture file at `path` that match
        `display_filter` (all when `None`), dissected as they are iterated.
        Reading starts a fresh capture: frame numbers and conversations
        start over, and a read in progress ends."""
        with self._calls:
            try:
                self._live().open_file(os.fspath(path), display_filter or "")
            except GuatiaoError as error:
                raise _refused(error) from error
        return self._frames()

    def _frames(self) -> Iterator[Dissected]:
        while True:
            with self._calls:
                try:
                    answer = self._live().next()
                except GuatiaoError as error:
                    raise _refused(error) from error
            try:
                frame = answer.to_python()
            finally:
                answer.close()
            if not frame:
                return
            yield Dissected.from_map(frame)

    def close(self) -> None:
        """Ends the session; Wireshark itself stays started for the process."""
        global _open
        with self._calls:
            session, self._session = self._session, None
            if session is not None:
                session.close()
        with _lock:
            if _open is self:
                _open = None


def _preference(value: object) -> str:
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    return str(value)
