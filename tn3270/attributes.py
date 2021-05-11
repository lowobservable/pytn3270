"""
tn3270.attributes
~~~~~~~~~~~~~~~~~
"""

from enum import IntEnum

class Attribute:
    """Attribute."""

    def __init__(self, value):
        # TODO: Validate input - looks like there is a parity bit.
        self._original_value = value

        self.protected = bool(value & 0x20)
        self.numeric = bool(value & 0x10)
        self.skip = self.protected and self.numeric

        display = (value & 0x0c) >> 2

        self.intensified = (display == 2)
        self.hidden = (display == 3)

        self.modified = bool(value & 0x01)

    @property
    def value(self):
        # TODO: Reconstruct the entire attribute from parts, this assumes
        # modified is the only part that can change (which is true).
        return (self._original_value & 0xfe) | int(self.modified)

    def __repr__(self):
        return (f'<Attribute protected={self.protected}, numeric={self.numeric}, '
                f'skip={self.skip}, intensified={self.intensified}, '
                f'hidden={self.hidden}, modified={self.modified}>')

class ExtendedAttributeType(IntEnum):
    """Extended attribute type."""

    ALL = 0x00
    HIGHLIGHT = 0x41
    FOREGROUND_COLOR = 0x42

class ExtendedAttribute:
    """Extended attribute."""

    def __init__(self, type_, value):
        self.type_ = type_
        self.value = value

    def __repr__(self):
        return f'<ExtendedAttribute type={self.type_}, value={self.value}>'

class AllExtendedAttribute(ExtendedAttribute):
    """Reset all character attributes extended attribute."""

    def __init__(self, type_, value):
        super().__init__(type_, value)

class Highlight(IntEnum):
    """Highlight."""

    NORMAL = 0xf0
    BLINK = 0xf1
    REVERSE = 0xf2
    UNDERSCORE = 0xf4
    INTENSIFY = 0xf8

class HighlightExtendedAttribute(ExtendedAttribute):
    """Highlight extended attribute."""

    def __init__(self, type_, value):
        super().__init__(type_, value)

        self.blink = False
        self.reverse = False
        self.underscore = False

        if value == Highlight.BLINK:
            self.blink = True
        elif value == Highlight.REVERSE:
            self.reverse = True
        elif value == Highlight.UNDERSCORE:
            self.underscore = True

    def __repr__(self):
        return (f'<HighlightExtendedAttribute blink={self.blink}, '
                f'reverse={self.reverse}, underscore={self.underscore}>')

class Color(IntEnum):
    """Color."""

    NEUTRAL = 0x00
    BLUE = 0xf1
    RED = 0xf2
    PINK = 0xf3
    GREEN = 0xf4
    TURQUOISE = 0xf5
    YELLOW = 0xf6
    WHITE = 0xf7

class ForegroundColorExtendedAttribute(ExtendedAttribute):
    """Foreground extended attribute."""

    def __init__(self, type_, value):
        super().__init__(type_, value)

        self.color = value

    def __repr__(self):
        return f'<ForegroundColorExtendedAttribute color={self.color}>'
