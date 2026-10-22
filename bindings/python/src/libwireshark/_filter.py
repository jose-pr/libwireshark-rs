"""A display-filter function written as a class: `NAME(field)` in a display
filter, from Wireshark 4.4.

```python
class PyDouble(provide.Provider, FilterFunction):
    NAME = "py_double"
    RETURNS = FilterReturn.COUNT

    def apply(self, value: Union[int, str]) -> Optional[int]:
        return value * 2 if isinstance(value, int) else None
```
"""

from __future__ import annotations

__all__ = ["FilterFunction", "FilterReturn"]

from enum import Enum
from typing import Any, ClassVar, Dict, Optional, Union

from . import kinds


class FilterReturn(str, Enum):
    """What a filter function answers, spelled as the description map spells it."""

    COUNT = "count"
    "An unsigned 32-bit number."
    TEXT = "text"
    "Text."


class FilterFunction(kinds.FilterFunction):
    """A display-filter function: subclass it beside guatiao's `provide.Provider`.

    `NAME` is its name in a display filter (`[a-z][a-z0-9_]*`), `RETURNS`
    what it answers. `apply` gets each value of the field passed: an `int`
    for an integer field, else the text Wireshark displays; it answers an
    `int` (for `COUNT`), a `str` (for `TEXT`), or `None` for no answer.
    """

    NAME: ClassVar[str]
    RETURNS: ClassVar[FilterReturn] = FilterReturn.COUNT

    def apply(self, value: Union[int, str]) -> Optional[Union[int, str]]:
        raise NotImplementedError

    def describe(self) -> Dict[str, Any]:
        return {
            "name": type(self).NAME,
            "returns": FilterReturn(type(self).RETURNS).value,
        }

    def call(self, value: Any) -> Any:  # type: ignore[override]
        argument = value.to_python()
        if isinstance(argument, bool) or not isinstance(argument, (int, str)):
            return None
        return self.apply(argument)
