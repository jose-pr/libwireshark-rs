"""An audio codec written as classes: RTP payloads decoded for Wireshark's
RTP player and sharkd's audio download.

```python
class Pyl8Decoder(Decoder):
    def __init__(self, format: StreamFormat) -> None:
        self.rate = format.sample_rate or 8000

    def sample_rate(self) -> int:
        return self.rate

    def decode(self, payload: bytes) -> List[int]:
        return [(byte - 128) << 8 for byte in payload]


class Pyl8(provide.Provider, Codec):
    NAME = "PYL8"
    DECODER = Pyl8Decoder
```
"""

from __future__ import annotations

__all__ = ["Codec", "Decoder", "StreamFormat"]

import logging
import struct
from dataclasses import dataclass
from typing import Any, ClassVar, Dict, Optional, Sequence, Type

from . import kinds

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class StreamFormat:
    """A stream's format, as its SDP announced it."""

    sample_rate: Optional[int] = None
    channels: Optional[int] = None


class Decoder:
    """One stream's decoder, made with its `StreamFormat`."""

    def __init__(self, format: StreamFormat) -> None:
        self.format = format

    def sample_rate(self) -> int:
        """The decoded samples per second."""
        raise NotImplementedError

    def channels(self) -> int:
        """Interleaved channels in the decoded samples."""
        return 1

    def decoded_len(self, payload: bytes) -> int:
        """How many samples `payload` decodes to, at most."""
        return len(payload)

    def decode(self, payload: bytes) -> Sequence[int]:
        """The 16-bit signed samples `payload` decodes to."""
        raise NotImplementedError


class _Decoding:
    """A `Decoder` as the `wireshark_decoder` object the host owns. Its slots
    cannot report a failure, so one is logged and answers nothing."""

    def __init__(self, decoder: Decoder) -> None:
        self.decoder = decoder

    def _answer(self, slot: str, call: Any, otherwise: int) -> int:
        try:
            return int(call())
        except Exception:
            _log.exception("%s.%s", type(self.decoder).__name__, slot)
            return otherwise

    def sample_rate(self) -> int:
        return self._answer("sample_rate", self.decoder.sample_rate, 0)

    def channels(self) -> int:
        return self._answer("channels", self.decoder.channels, 1)

    def decoded_len(self, payload: bytes) -> int:
        return self._answer("decoded_len", lambda: self.decoder.decoded_len(payload), 0)

    def decode(self, payload: bytes, samples: bytearray) -> int:
        def write() -> int:
            decoded = [
                max(-32768, min(32767, int(sample)))
                for sample in list(self.decoder.decode(payload))[: len(samples) // 2]
            ]
            struct.pack_into(f"<{len(decoded)}h", samples, 0, *decoded)
            return len(decoded)

        return self._answer("decode", write, 0)


class Codec(kinds.Codec):
    """An audio codec: subclass it beside guatiao's `provide.Provider`.

    `NAME` is the RTP encoding name it decodes, as an SDP `a=rtpmap` names
    it; `DECODER` the `Decoder` class each stream gets an instance of.
    """

    NAME: ClassVar[str]
    DECODER: ClassVar[Type[Decoder]] = Decoder

    def describe(self) -> Dict[str, Any]:
        return {"name": type(self).NAME}

    def open(self, format: Any) -> _Decoding:  # type: ignore[override]
        announced = format.to_python()
        stream = StreamFormat(sample_rate=announced.get("sample_rate"), channels=announced.get("channels"))
        return _Decoding(type(self).DECODER(stream))
