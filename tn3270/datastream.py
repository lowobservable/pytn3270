"""
tn3270.datastream
~~~~~~~~~~~~~~~~~
"""

from enum import Enum
import logging

# http://www.prycroft6.com.au/misc/3270.html
# https://www.tommysprinkle.com/mvs/P3270/start.htm
# https://www.ibm.com/support/knowledgecenter/en/SSGMGV_3.1.0/com.ibm.cics.ts31.doc/dfhp3/dfhp3bg.htm#DFHP3BG

logger = logging.getLogger(__name__)

class Command(Enum):
    """Command."""

    W = 0x01    # Write
    RB = 0x02   # Read Buffer
    NOP = 0x03
    EW = 0x05   # Erase / Write
    RM = 0x06   # Read Modified
    EWA = 0x0d  # Erase / Write Alternate
    RMA = 0x0e  # Read Modified All
    EAU = 0x0f  # Erase All Unprotected
    WSF = 0x11  # Write Structured Field

COMMAND_MAP = {
    **{command.value: command for command in Command},

    # SNA
    0x63: Command.RMA,
    0x6f: Command.EAU,
    0x7e: Command.EWA,
    0xf1: Command.W,
    0xf2: Command.RB,
    0xf3: Command.WSF,
    0xf5: Command.EW,
    0xf6: Command.RM
}

class WCC:
    """Write control character."""

    def __init__(self, value):
        # TODO: Validate input.
        self.value = value

        self.reset = bool(value & 0x40)
        self.alarm = bool(value & 0x04)
        self.unlock_keyboard = bool(value & 0x02)
        self.reset_modified = bool(value & 0x01)

    def __repr__(self):
        return (f'<WCC reset={self.reset}, alarm={self.alarm}, '
                f'unlock_keyboard={self.unlock_keyboard}, '
                f'reset_modified={self.reset_modified}>')

class Order(Enum):
    """Order."""

    PT = 0x05   # Program Tab
    GE = 0x08   # Graphic Escape
    SBA = 0x11  # Set Buffer Address
    EUA = 0x12  # Erase Unprotected to Address
    IC = 0x13   # Insert Cursor
    SF = 0x1d   # Start Field
    SA = 0x28   # Set Attribute
    SFE = 0x29  # Start Field Extended
    MF = 0x2c   # Modify Field
    RA = 0x3c   # Repeat to Address

ORDERS = {order.value for order in Order}

class Attribute:
    """Attribute."""

    def __init__(self, value):
        # TODO: Validate input - looks like there is a parity bit.
        self.value = value

        self.protected = bool(value & 0x20)
        self.numeric = bool(value & 0x10)
        self.skip = self.protected and self.numeric

        display = (value & 0x0c) >> 2

        self.intensified = (display == 2)
        self.hidden = (display == 3)

        self.modified = bool(value & 0x01)

    def __repr__(self):
        return (f'<Attribute protected={self.protected}, numeric={self.numeric}, '
                f'skip={self.skip}, intensified={self.intensified}, '
                f'hidden={self.hidden}, modified={self.modified}>')

class AID(Enum):
    """Attention identifier."""

    NONE = 0x60
    STRUCTURED_FIELD = 0x88
    CLEAR = 0x6d
    ENTER = 0x7d
    PA1 = 0x6c
    PA2 = 0x6e
    PA3 = 0x6b
    PF1 = 0xf1
    PF2 = 0xf2
    PF3 = 0xf3
    PF4 = 0xf4
    PF5 = 0xf5
    PF6 = 0xf6
    PF7 = 0xf7
    PF8 = 0xf8
    PF9 = 0xf9
    PF10 = 0x7a
    PF11 = 0x7b
    PF12 = 0x7c
    PF13 = 0xc1
    PF14 = 0xc2
    PF15 = 0xc3
    PF16 = 0xc4
    PF17 = 0xc5
    PF18 = 0xc6
    PF19 = 0xc7
    PF20 = 0xc8
    PF21 = 0xc9
    PF22 = 0x4a
    PF23 = 0x4b
    PF24 = 0x4c

SHORT_READ_AIDS = [AID.CLEAR, AID.PA1, AID.PA2, AID.PA3]

def parse_outbound_message(bytes_):
    """Parse a message from the host."""
    command_byte = bytes_[0]

    command = COMMAND_MAP.get(command_byte)

    if command is None:
        raise ValueError(f'Unrecognized command 0x{command_byte:02x}')

    if command == Command.EWA:
        raise NotImplementedError('EWA command is not supported')

    if command == Command.WSF:
        raise NotImplementedError('WSF command is not supported')

    if command in [Command.W, Command.EW]:
        # TODO: Validate size.

        wcc = WCC(bytes_[1])
        orders = list(parse_orders(bytes_[2:]))

        return (command, wcc, orders)

    return (command,)

def format_inbound_read_buffer_message(aid, cursor_address, orders):
    """Format a read buffer message for the host."""
    bytes_ = bytearray()

    for (order, data) in orders:
        if order == Order.SF:
            bytes_.extend([Order.SF.value, data[0].value])
        elif order is None:
            bytes_ += data

    return _format_inbound_message(aid, cursor_address, bytes_)

def format_inbound_read_modified_message(aid, cursor_address, fields, all_=False):
    """Format a read modified message for the host."""
    if aid in SHORT_READ_AIDS and not all_:
        return bytearray([aid.value])

    bytes_ = bytearray()

    for (address, data) in fields:
        bytes_.append(Order.SBA.value)

        bytes_ += format_address(address)

        bytes_.extend([byte for byte in data if byte != 0x00])

    return _format_inbound_message(aid, cursor_address, bytes_)

def parse_orders(bytes_):
    """Parse orders from the host."""
    data = bytearray()

    index = 0

    while index < len(bytes_):
        byte = bytes_[index]

        if byte in ORDERS:
            if data:
                yield (None, data)

                data = bytearray()

            order = Order(byte)
            parameters = None

            index += 1

            if order == Order.PT:
                pass
            elif order == Order.GE:
                raise NotImplementedError('GE order is not supported')
            elif order == Order.SBA:
                parameters = [parse_address(bytes_[index:index+2])[0]]
                index += 2
            elif order == Order.EUA:
                parameters = [parse_address(bytes_[index:index+2])[0]]
                index += 2
            elif order == Order.IC:
                pass
            elif order == Order.SF:
                parameters = [Attribute(bytes_[index])]
                index += 1
            elif order == Order.SA:
                raise NotImplementedError('SA order is not supported')
            elif order == Order.SFE:
                raise NotImplementedError('SFE order is not supported')
            elif order == Order.MF:
                raise NotImplementedError('MF order is not supported')
            elif order == Order.RA:
                parameters = [parse_address(bytes_[index:index+2])[0], bytes_[index+2]]
                index += 3

            yield (order, parameters)
        else:
            if byte == 0x00 or (byte >= 0x40 and byte <= 0xfe):
                data.append(byte)
            else:
                logger.warning(f'Value 0x{byte:02x} out of range')

            index += 1

    if data:
        yield (None, data)

def parse_address(bytes_, size=None):
    """Parse an address."""
    if size == 16:
        return((bytes_[0] << 8) | bytes_[1], 16)

    setting = (bytes_[0] & 0xc0) >> 6

    # Handle a 12-bit address.
    if setting in [0b01, 0b11]:
        return (((bytes_[0] & 0x3f) << 6) | (bytes_[1] & 0x3f), 12)

    # Assume a 14-bit address.
    return (((bytes_[0] & 0x3f) << 8) | bytes_[1], 14)

# https://www.tommysprinkle.com/mvs/P3270/iocodes.htm
SIX_BIT_CHARACTER_MAP = [
    0x40, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
]

def format_address(address, size=14):
    """Format an address."""

    # TODO: Validate that the address is within range based on size.

    if size == 16:
        return bytes([(address >> 8) & 0xff, address & 0xff])

    if size == 14:
        return bytes([(address >> 8) & 0x3f, address & 0xff])

    if size == 12:
        return bytes([SIX_BIT_CHARACTER_MAP[(address >> 6) & 0x3f],
                      SIX_BIT_CHARACTER_MAP[address & 0x3f]])

    raise ValueError('Invalid size')

def _format_inbound_message(aid, cursor_address, data_bytes):
    message_bytes = bytearray([aid.value])

    message_bytes += format_address(cursor_address)
    message_bytes += data_bytes

    return message_bytes
