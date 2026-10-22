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

import struct
from dataclasses import dataclass
from typing import Any, ClassVar, Dict, Optional, Sequence, Type

from . import kinds


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
    """A `Decoder` as the `wireshark_decoder` object the host owns."""

    def __init__(self, decoder: Decoder) -> None:
        self.decoder = decoder

    def sample_rate(self) -> int:
        return int(self.decoder.sample_rate())

    def channels(self) -> int:
        return int(self.decoder.channels())

    def decoded_len(self, payload: bytes) -> int:
        return int(self.decoder.decoded_len(payload))

    def decode(self, payload: bytes, samples: bytearray) -> int:
        decoded = list(self.decoder.decode(payload))[: len(samples) // 2]
        struct.pack_into(f"<{len(decoded)}h", samples, 0, *decoded)
        return len(decoded)


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
