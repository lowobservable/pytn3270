"""
tn3270.datastream
~~~~~~~~~~~~~~~~~
"""

from enum import Enum
import logging

from .attributes import Attribute, ExtendedAttributeType, ExtendedAttribute, \
                        HighlightExtendedAttribute, ForegroundColorExtendedAttribute

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

    if command in [Command.W, Command.EW, Command.EWA]:
        # TODO: Validate size.

        wcc = WCC(bytes_[1])
        orders = list(parse_orders(bytes_[2:]))

        return (command, wcc, orders)

    if command == Command.WSF:
        structured_fields = list(parse_outbound_structured_fields(bytes_[1:]))

        return (command, structured_fields)

    return (command,)

def format_inbound_read_buffer_message(aid, cursor_address, orders):
    """Format a read buffer message for the host."""
    bytes_ = bytearray()

    for (order, data) in orders:
        if order == Order.SF:
            bytes_.extend([Order.SF.value, data[0].value])
        elif order == Order.GE:
            bytes_.extend([Order.GE.value, data[0]])
        elif order is None:
            bytes_ += data
        else:
            raise NotImplementedError(f'{order} is not supported')

    return _format_inbound_message(aid, cursor_address, bytes_)

def format_inbound_read_modified_message(aid, cursor_address, orders, all_=False):
    """Format a read modified message for the host."""
    if aid in SHORT_READ_AIDS and not all_:
        return bytearray([aid.value])

    bytes_ = bytearray()

    for (order, data) in orders:
        if order == Order.SBA:
            bytes_.append(Order.SBA.value)
            bytes_.extend(format_address(data[0]))
        elif order == Order.SF:
            bytes_.extend([Order.SF.value, data[0].value])
        elif order == Order.GE:
            bytes_.extend([Order.GE.value, data[0]])
        elif order is None:
            bytes_ += data
        else:
            raise NotImplementedError(f'{order} is not supported')

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
                # TODO: validate size
                parameters = [bytes_[index]]
                index += 1
            elif order == Order.SBA:
                # TODO: validate size
                parameters = [parse_address(bytes_[index:index+2])[0]]
                index += 2
            elif order == Order.EUA:
                # TODO: validate size
                parameters = [parse_address(bytes_[index:index+2])[0]]
                index += 2
            elif order == Order.IC:
                pass
            elif order == Order.SF:
                parameters = [Attribute(bytes_[index])]
                index += 1
            elif order == Order.SA:
                # TODO: validate size
                parameters = [parse_extended_attribute(bytes_[index:index+2])]
                index += 2
            elif order == Order.SFE:
                # TODO: validate size
                attribute = None
                extended_attributes = []

                count = bytes_[index]
                index += 1

                for attribute_index in range(index, index + (count * 2), 2):
                    if bytes_[attribute_index] == 0xc0:
                        attribute = Attribute(bytes_[attribute_index+1])
                    else:
                        extended_attributes.append(parse_extended_attribute(bytes_[attribute_index:attribute_index+2]))

                parameters = [attribute, extended_attributes]
                index += count * 2
            elif order == Order.MF:
                raise NotImplementedError('MF order is not supported')
            elif order == Order.RA:
                # TODO: validate size
                stop_address = parse_address(bytes_[index:index+2])[0]
                index += 2

                # Peek ahead to detect a GE order.
                is_ge = False

                if bytes_[index] == Order.GE.value:
                    is_ge = True
                    index += 1

                parameters = [stop_address, bytes_[index], is_ge]
                index += 1

            yield (order, parameters)
        else:
            if byte == 0x00 or (byte >= 0x40 and byte <= 0xfe):
                data.append(byte)
            else:
                logger.warning(f'Value 0x{byte:02x} out of range')

            index += 1

    if data:
        yield (None, data)

def parse_outbound_structured_fields(bytes_):
    """Parse structured fields from the host."""
    index = 0

    while index < len(bytes_):
        remaining_length = len(bytes_) - index

        if remaining_length < 2:
            raise Exception('Invalid structured field')

        length = (bytes_[index] << 8) | bytes_[index+1]

        if length == 0:
            length = remaining_length

        if length < 3:
            raise Exception(f'Invalid structured field length: {length} must be at least 3')

        if length > remaining_length:
            raise Exception(f'Invalid structured field length: {length} greater than remaining {remaining_length} bytes')

        id_ = bytes_[index+2]

        data_length = length - 3
        data = bytes_[index+3:index+3+data_length]

        yield (id_, data)

        index += length

def format_inbound_structured_fields(structured_fields):
    """Format structured fields for the host."""
    bytes_ = bytearray([AID.STRUCTURED_FIELD.value])

    for (id_, data) in structured_fields:
        length = len(data) + 3

        bytes_.extend([(length >> 8) & 0xff, length & 0xff, id_])

        bytes_ += data

    return bytes_

def parse_extended_attribute(bytes_):
    """Parse an extended attribute."""

    if len(bytes_) != 2:
        raise Exception('Invalid extended attribute')

    type_ = bytes_[0]
    value = bytes_[1]

    if type_ == ExtendedAttributeType.HIGHLIGHT:
        return HighlightExtendedAttribute(type_, value)
    elif type_ == ExtendedAttributeType.FOREGROUND_COLOR:
        return ForegroundColorExtendedAttribute(type_, value)

    logger.warning(f'Extended attribute 0x{type_:02x} not supported')

    return ExtendedAttribute(type_, value)

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

def format_address(address, size=12):
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
