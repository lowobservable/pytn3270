"""
tn3270.emulator
~~~~~~~~~~~~~~~
"""

from enum import Enum
from itertools import chain
import struct
import logging

from .datastream import Command, WCC, Order, AID, parse_outbound_message, \
                        format_inbound_read_buffer_message, \
                        format_inbound_read_modified_message, \
                        format_inbound_structured_fields
from .attributes import Attribute, HighlightExtendedAttribute, \
                        ForegroundColorExtendedAttribute
from .structured_fields import StructuredField, ReadPartitionType, \
                               QueryListRequestType, QueryCode
from .ebcdic import DUP, FM

class CharacterSet(Enum):
    """Display cell character set."""

    GE = 1

class CellFormatting:
    """Display cell formatting."""

    def __init__(self, formatting=None, extended_attributes=None):
        self.blink = False
        self.reverse = False
        self.underscore = False
        self.color = 0x00

        if formatting is not None:
            self.blink = formatting.blink
            self.reverse = formatting.reverse
            self.underscore = formatting.underscore
            self.color = formatting.color

        if extended_attributes is not None:
            for extended_attribute in extended_attributes:
                self._apply_extended_attribute(extended_attribute)

    def _apply_extended_attribute(self, extended_attribute):
        if isinstance(extended_attribute, HighlightExtendedAttribute):
            self.blink = extended_attribute.blink
            self.reverse = extended_attribute.reverse
            self.underscore = extended_attribute.underscore
        elif isinstance(extended_attribute, ForegroundColorExtendedAttribute):
            self.color = extended_attribute.color

    def __eq__(self, other):
        if not isinstance(other, CellFormatting):
            return False

        return other.blink == self.blink and other.reverse == self.reverse and \
               other.underscore == self.underscore and other.color == self.color

class Cell:
    """A display cell."""

    def __init__(self, formatting):
        self.formatting = formatting

class AttributeCell(Cell):
    """A attribute display cell."""

    def __init__(self, attribute, formatting=None):
        super().__init__(formatting)

        self.attribute = attribute

class CharacterCell(Cell):
    """A character display cell."""

    def __init__(self, byte, character_set=None, formatting=None):
        super().__init__(formatting)

        self.byte = byte
        self.character_set = character_set

class OperatorError(Exception):
    """Operator error."""

class ProtectedCellOperatorError(OperatorError):
    """Protected cell error."""

class FieldOverflowOperatorError(OperatorError):
    """Field overflow error."""

class Emulator:
    """TN3270 emulator."""

    def __init__(self, stream, rows, columns):
        self.logger = logging.getLogger(__name__)

        # TODO: Validate that stream has read_multiple() and write() methods.
        self.stream = stream
        self.rows = rows
        self.columns = columns

        self.cells = [CharacterCell(0x00) for index in range(self.rows * self.columns)]
        self.dirty = set(range(self.rows * self.columns))

        self.address = 0
        self.cursor_address = 0

        self.current_aid = AID.NONE
        self.keyboard_locked = True

    def update(self, **kwargs):
        """Read and execute outbound messages."""
        records = self.stream.read_multiple(**kwargs)

        if not records:
            return False

        for bytes_ in records:
            (command, *options) = parse_outbound_message(bytes_)

            self._execute(command, *options)

        return True

    def aid(self, aid):
        """AID key."""
        if aid == AID.CLEAR:
            self._clear()

        self.current_aid = aid
        self.keyboard_locked = True

        self._read_modified()

    def tab(self, direction=1):
        """Tab or backtab key."""
        address = self._calculate_tab_address(self.cursor_address, direction)

        if address is not None:
            self.cursor_address = address

    def newline(self):
        """Move to the next line or the subsequent unprotected field."""
        current_row = self.cursor_address // self.columns

        address = self._wrap_address((current_row + 1) * self.columns)

        (attribute, attribute_address) = self.find_attribute(address)

        if attribute is not None and not attribute.protected and attribute_address != address:
            self.cursor_address = address
            return

        address = self._calculate_tab_address(address, direction=1)

        if address is not None:
            self.cursor_address = address

    def home(self):
        """Home key."""
        addresses = self._get_addresses(0, (self.rows * self.columns) - 1)

        address = next((address for address in addresses
                        if isinstance(self.cells[address], AttributeCell)
                        and not self.cells[address].attribute.protected), None)

        if address is not None:
            self.cursor_address = self._wrap_address(address + 1)

    def cursor_up(self):
        """Cursor up key."""
        self.cursor_address = self._wrap_address(self.cursor_address - self.columns)

    def cursor_down(self):
        """Cursor down key."""
        self.cursor_address = self._wrap_address(self.cursor_address + self.columns)

    def cursor_left(self, rate=1):
        """Cursor left key."""
        if rate < 1 or rate > 2:
            raise ValueError('Invalid rate')

        self.cursor_address = self._wrap_address(self.cursor_address - rate)

    def cursor_right(self, rate=1):
        """Cursor right key."""
        if rate < 1 or rate > 2:
            raise ValueError('Invalid rate')

        self.cursor_address = self._wrap_address(self.cursor_address + rate)

    def input(self, byte, insert=False):
        """Single character input."""
        self._input(byte, insert=insert)

    def dup(self, insert=False):
        """Duplicate (DUP) key."""
        self._input(DUP, insert=insert, move=False)

        # TODO: Moving to the next unprotected field should be reusable - should the
        # calculate_tab_address method be refactored to be more generic or at least
        # a single next_unprotected filter?
        addresses = self._get_addresses(self.cursor_address,
                                        self._wrap_address(self.cursor_address - 1))

        address = next((address for address in addresses
                        if isinstance(self.cells[address], AttributeCell)
                        and not self.cells[address].attribute.protected), None)

        if address is not None:
            self.cursor_address = self._wrap_address(address + 1)

    def field_mark(self, insert=False):
        """Field mark (FM) key."""
        self._input(FM, insert=insert)

    def backspace(self):
        """Backspace key."""
        if isinstance(self.cells[self.cursor_address], AttributeCell):
            raise ProtectedCellOperatorError

        (start_address, end_address, attribute) = self.get_field(self.cursor_address)

        if self.cursor_address == start_address:
            return

        self._shift_left(self._wrap_address(self.cursor_address - 1), end_address)

        attribute.modified = True

        self.cursor_address = self._wrap_address(self.cursor_address - 1)

    def delete(self):
        """Delete key."""
        if isinstance(self.cells[self.cursor_address], AttributeCell):
            raise ProtectedCellOperatorError

        (_, end_address, attribute) = self.get_field(self.cursor_address)

        self._shift_left(self.cursor_address, end_address)

        attribute.modified = True

    def erase_end_of_field(self):
        """Erase end of field (EOF) key."""
        if isinstance(self.cells[self.cursor_address], AttributeCell):
            raise ProtectedCellOperatorError

        (_, end_address, attribute) = self.get_field(self.cursor_address)

        for address in self._get_addresses(self.cursor_address, end_address):
            self._write_character(address, 0x00, preserve=True)

        attribute.modified = True

    def erase_input(self):
        """Erase input key."""
        for (start_address, end_address, attribute) in self.get_fields():
            for address in self._get_addresses(start_address, end_address):
                self._write_character(address, 0x00, preserve=True)

            attribute.modified = False

        # TODO: Confirm behavior but I think this should reposition the cursor to the
        # first character location, after the field attribute, in the first unprotected
        # field of the partition's character buffer - it is the same as Erase All
        # Unprotected.

    def get_bytes(self, start_address, end_address):
        """Get character cell bytes."""
        addresses = self._get_addresses(start_address, end_address)

        return bytes([self.cells[address].byte if isinstance(self.cells[address], CharacterCell) else 0x00 for address in addresses])

    def get_field(self, address):
        """Get the unprotected field containing or starting at the address."""
        (attribute, start_attribute_address) = self.find_attribute(address)

        if attribute is None or attribute.protected:
            raise ProtectedCellOperatorError

        start_address = self._wrap_address(start_attribute_address + 1)

        # By using the field start attribute address as the search end address we know
        # there will be at least one attribute byte found even in the case of a single
        # field.
        addresses = self._get_addresses(start_address, start_attribute_address)

        end_attribute_address = next((address for address in addresses
                                      if isinstance(self.cells[address], AttributeCell)))

        end_address = self._wrap_address(end_attribute_address - 1)

        return (start_address, end_address, attribute)

    def get_fields(self):
        """Get all unprotected fields."""
        fields = []

        for address in range(0, self.rows * self.columns):
            cell = self.cells[address]

            if isinstance(cell, AttributeCell) and not cell.attribute.protected:
                field = self.get_field(address)

                fields.append(field)

        return fields

    def find_attribute(self, address):
        """Find the applicable attribute for the address."""
        addresses = self._get_addresses(address, self._wrap_address(address + 1),
                                        direction=-1)

        for address in addresses:
            cell = self.cells[address]

            if isinstance(cell, AttributeCell):
                return (cell.attribute, address)

        return (None, None)

    def alarm(self):
        """Alarm stub."""
        pass

    def _execute(self, command, *options):
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('Execute')
            self.logger.debug(f'\tData    = {bytes_}')
            self.logger.debug(f'\tCommand = {command}')

        if command == Command.W:
            self._write(*options)
        elif command == Command.RB:
            self._read_buffer()
        elif command == Command.NOP:
            pass
        elif command in [Command.EW, Command.EWA]:
            self._erase()
            self._write(*options)
        elif command == Command.RM:
            self._read_modified()
        elif command == Command.RMA:
            self._read_modified(all_=True)
        elif command == Command.EAU:
            self._erase_all_unprotected()
        elif command == Command.WSF:
            self._write_structured_fields(*options)

    def _erase(self):
        self.logger.debug('Erase')

        self._clear()

    def _erase_all_unprotected(self):
        self.logger.debug('Erase All Unprotected')

        for (start_address, end_address, attribute) in self.get_fields():
            for address in self._get_addresses(start_address, end_address):
                self._write_character(address, 0x00, preserve=True)

            attribute.modified = False

        self.current_aid = AID.NONE
        self.keyboard_locked = False

        # TODO: Repositions the cursor to the first character location, after the field
        # attribute, in the first unprotected field of the partition's character buffer.

    def _write(self, wcc, orders):
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('Write')
            self.logger.debug(f'\tWCC = {wcc}')

        if wcc.reset_modified:
            for cell in self.cells:
                if isinstance(cell, AttributeCell):
                    cell.attribute.modified = False

        formatting = None
        character_set = None

        for (order, data) in orders:
            if self.logger.isEnabledFor(logging.DEBUG):
                if order is None:
                    self.logger.debug(f'\t{data}')
                else:
                    self.logger.debug(f'\t{order}')
                    self.logger.debug(f'\t\tParameters = {data}')

            if order == Order.PT:
                # TODO: Implement additional PT cases
                if isinstance(self.cells[self.address], AttributeCell) and not self.cells[self.address].attribute.protected:
                    self.address = self._wrap_address(self.address + 1)
                else:
                    raise NotImplementedError('PT order is not fully supported')
            elif order == Order.GE:
                self._write_character(self.address, data[0], CharacterSet.GE, formatting)

                self.address = self._wrap_address(self.address + 1)
            elif order == Order.SBA:
                if data[0] >= (self.rows * self.columns):
                    self.logger.warning(f'Address {data[0]} is out of range')
                else:
                    self.address = data[0]
            elif order == Order.EUA:
                stop_address = data[0]

                # TODO: Validate stop_address is in range...
                end_address = self._wrap_address(stop_address - 1)

                addresses = self._get_addresses(self.address, end_address)
                unprotected_addresses = self._get_unprotected_addresses()

                for address in unprotected_addresses.intersection(addresses):
                    self._write_character(address, 0x00, preserve=True)

                self.address = stop_address
            elif order == Order.IC:
                self.cursor_address = self.address
            elif order == Order.SF:
                formatting = None

                self._write_attribute(self.address, data[0], formatting)

                self.address = self._wrap_address(self.address + 1)
            elif order == Order.SA:
                formatting = CellFormatting(formatting, extended_attributes=[data[0]])
            elif order == Order.SFE:
                # TODO: Confirm that formatting should be reset here
                formatting = CellFormatting(None, extended_attributes=data[1])

                self._write_attribute(self.address, data[0] or Attribute(0), formatting)

                self.address = self._wrap_address(self.address + 1)
            elif order == Order.MF:
                raise NotImplementedError('MF order is not supported')
            elif order == Order.RA:
                (stop_address, byte, is_ge) = data

                # TODO: Validate stop_address is in range...
                end_address = self._wrap_address(stop_address - 1)

                addresses = self._get_addresses(self.address, end_address)

                for address in addresses:
                    self._write_character(address, byte, CharacterSet.GE if is_ge else character_set, formatting)

                self.address = stop_address
            elif order is None:
                for byte in data:
                    self._write_character(self.address, byte, character_set, formatting)

                    self.address = self._wrap_address(self.address + 1)

        if wcc.unlock_keyboard:
            self.current_aid = AID.NONE
            self.keyboard_locked = False

        if wcc.alarm:
            self.alarm()

    def _clear(self):
        for address in range(self.rows * self.columns):
            self._write_character(address, 0x00, None, None)

        self.address = 0
        self.cursor_address = 0

    def _read_buffer(self):
        orders = self._generate_inbound_orders(0, (self.rows * self.columns) - 1)

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('Read Buffer')
            self.logger.debug(f'\tAID    = {self.current_aid}')
            self.logger.debug(f'\tOrders = {orders}')

        bytes_ = format_inbound_read_buffer_message(self.current_aid, self.cursor_address, orders)

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f'\tData   = {bytes_}')

        self.stream.write(bytes_)

    def _read_modified(self, all_=False):
        modified_field_ranges = [(start_address, end_address) for (start_address, end_address, attribute) in self.get_fields() if attribute.modified]

        orders = []

        for (start_address, end_address) in modified_field_ranges:
            orders.append((Order.SBA, [start_address]))

            orders.extend(self._generate_inbound_orders(start_address, end_address, filter_null=True))

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('Read Modified')
            self.logger.debug(f'\tAID    = {self.current_aid}')
            self.logger.debug(f'\tOrders = {orders}')
            self.logger.debug(f'\tAll    = {all_}')

        bytes_ = format_inbound_read_modified_message(self.current_aid, self.cursor_address, orders, all_)

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f'\tData   = {bytes_}')

        self.stream.write(bytes_)

    def _input(self, byte, insert=False, move=True):
        if isinstance(self.cells[self.cursor_address], AttributeCell):
            raise ProtectedCellOperatorError

        (_, end_address, attribute) = self.get_field(self.cursor_address)

        if attribute is None or attribute.protected:
            raise ProtectedCellOperatorError

        # TODO: Implement numeric field validation.

        if insert and self.cells[self.cursor_address].byte != 0x00:
            addresses = self._get_addresses(self.cursor_address, end_address)

            first_null_address = next((address for address in addresses
                                       if self.cells[address].byte == 0x00), None)

            if first_null_address is None:
                raise FieldOverflowOperatorError

            self._shift_right(self.cursor_address, first_null_address)

        self._write_character(self.cursor_address, byte, preserve=True)

        attribute.modified = True

        if not move:
            return

        self.cursor_address = self._wrap_address(self.cursor_address + 1)

        # TODO: Is this correct - does this only happen if skip?
        if isinstance(self.cells[self.cursor_address], AttributeCell):
            skip = self.cells[self.cursor_address].attribute.skip

            addresses = self._get_addresses(self.cursor_address,
                                            self._wrap_address(self.cursor_address - 1))

            address = next((address for address in addresses
                            if isinstance(self.cells[address], AttributeCell)
                            and (not skip or (skip and not self.cells[address].attribute.protected))), None)

            if address is not None:
                self.cursor_address = self._wrap_address(address + 1)

    def _get_addresses(self, start_address, end_address, direction=1):
        if direction < 0:
            if end_address > start_address:
                return chain(reversed(range(0, start_address + 1)),
                             reversed(range(end_address, self.rows * self.columns)))

            return reversed(range(end_address, start_address + 1))

        if end_address < start_address:
            return chain(range(start_address, self.rows * self.columns),
                         range(0, end_address + 1))

        return range(start_address, end_address + 1)

    def _wrap_address(self, address):
        if address < 0 or address >= (self.rows * self.columns):
            return address % (self.rows * self.columns)

        return address

    def _get_unprotected_addresses(self):
        addresses = set()

        for (start_address, end_address, _) in self.get_fields():
            addresses.update(self._get_addresses(start_address, end_address))

        return addresses

    def _calculate_tab_address(self, address, direction):
        if direction < 0:
            if address > 0 and isinstance(self.cells[address - 1], AttributeCell):
                address -= 1

            start_address = self._wrap_address(address - 1)
            end_address = self._wrap_address(address)
        else:
            start_address = self._wrap_address(address)
            end_address = self._wrap_address(address - 1)

        addresses = self._get_addresses(start_address, end_address, direction)

        address = next((address for address in addresses
                        if isinstance(self.cells[address], AttributeCell)
                        and not self.cells[address].attribute.protected), None)

        if address is None:
            return None

        return self._wrap_address(address + 1)

    def _write_attribute(self, index, attribute, formatting=None, preserve=False):
        cell = self.cells[index]

        if preserve:
            formatting = cell.formatting

        if isinstance(cell, AttributeCell):
            if cell.attribute.value == attribute.value and cell.formatting == formatting:
                return False

            cell.attribute = attribute
            cell.formatting = formatting
        else:
            self.cells[index] = AttributeCell(attribute, formatting)

        self.dirty.add(index)

        return True

    def _write_character(self, index, byte, character_set=None, formatting=None, preserve=False):
        cell = self.cells[index]

        if preserve:
            character_set = cell.character_set
            formatting = cell.formatting

        if isinstance(cell, CharacterCell):
            if cell.byte == byte and cell.character_set == character_set and cell.formatting == formatting:
                return False

            cell.byte = byte
            cell.character_set = character_set
            cell.formatting = formatting
        else:
            self.cells[index] = CharacterCell(byte, character_set, formatting)

        self.dirty.add(index)

        return True

    def _shift_left(self, start_address, end_address):
        addresses = list(self._get_addresses(start_address, end_address))

        for (left_address, right_address) in zip(addresses, addresses[1:]):
            self._write_character(left_address, self.cells[right_address].byte, preserve=True)

        self._write_character(end_address, 0x00, preserve=True)

    def _shift_right(self, start_address, end_address):
        addresses = list(self._get_addresses(start_address, end_address))

        for (left_address, right_address) in reversed(list(zip(addresses, addresses[1:]))):
            self._write_character(right_address, self.cells[left_address].byte, preserve=True)

        self._write_character(start_address, 0x00, preserve=True)

    def _generate_inbound_orders(self, start_address, end_address, filter_null=False):
        orders = []

        data = bytearray()

        def eject():
            nonlocal data

            if data:
                orders.append((None, data))

                data = bytearray()

        for address in self._get_addresses(start_address, end_address):
            cell = self.cells[address]

            if isinstance(cell, AttributeCell):
                eject()

                orders.append((Order.SF, [cell.attribute]))
            elif isinstance(cell, CharacterCell):
                if not filter_null or cell.byte != 0x00:
                    if cell.character_set == CharacterSet.GE:
                        eject()

                        orders.append((Order.GE, [cell.byte]))
                    else:
                        data.append(cell.byte)

        eject()

        return orders

    def _write_structured_fields(self, structured_fields):
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('Write Structured Fields')
            self.logger.debug(f'\tFields = {structured_fields}')

        for (id_, data) in structured_fields:
            if id_ == StructuredField.READ_PARTITION:
                self._read_partition(data)
            elif id_ == StructuredField.OUTBOUND_3270DS:
                self._outbound_3270ds(data)
            else:
                raise NotImplementedError(f'Structured field 0x{id_:02x} not supported')

    def _read_partition(self, data):
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('Read Partition (Structured Field)')
            self.logger.debug(f'\tData = {data}')

        partition = data[0]
        type_ = data[1]

        if type_ == ReadPartitionType.QUERY:
            if partition != 0xff:
                self.logger.warning(f'Partition should be 0xff for query, received 0x{partition:02x}')

            self._query()
        elif type_ == ReadPartitionType.QUERY_LIST:
            if partition != 0xff:
                self.logger.warning(f'Partition should be 0xff for query list, received 0x{partition:02x}')

            request_type = QueryListRequestType(data[2])

            request_codes = None

            if request_type != QueryListRequestType.ALL:
                request_codes = [QueryCode(code) for code in data[3:]]

            self._query(request_type, request_codes)
        else:
            raise NotImplementedError(f'Read partition type 0x{type_:02x} not supported')

    def _outbound_3270ds(self, data):
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('Outbound 3270 DS (Structured Field)')
            self.logger.debug(f'\tData = {data}')

        partition = data[0]
        command = data[1]

        if partition != 0x00:
            self.logger.warning(f'Partition 0x{partition:02x} not supported')

        if command == 0xf1:
            self._write(WCC(data[2]), data[3:])
        elif command in [0xf5, 0x7e]:
            self._erase()
            self._write(WCC(data[2]), data[3:])
        elif command == 0x6f:
            self._erase_all_unprotected()
        else:
            raise NotImplementedError(f'Outbound 3270 DS command 0x{command:02x} not supported')

    def _query(self, request_type=None, request_codes=None):
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('Query')
            self.logger.debug(f'\tRequest Type  = {request_type}')
            self.logger.debug(f'\tRequest Codes = {request_codes}')

        codes = [
            QueryCode.USABLE_AREA, QueryCode.ALPHANUMERIC_PARTITIONS,
            QueryCode.REPLY_MODES, QueryCode.IMPLICIT_PARTITIONS
        ]

        if request_type == QueryListRequestType.LIST:
            codes = request_codes
        elif request_type == QueryListRequestType.EQUIVALENT_AND_LIST:
            if request_codes is not None:
                codes = set(codes + request_codes)

        # Generate the replies.
        replies = []

        for code in codes:
            reply = None

            if code == QueryCode.USABLE_AREA:
                reply = _query_usable_area(self.rows, self.columns)
            elif code == QueryCode.ALPHANUMERIC_PARTITIONS:
                reply = _query_alphanumeric_partitions(self.rows, self.columns)
            elif code == QueryCode.REPLY_MODES:
                reply = _query_reply_modes()
            elif code == QueryCode.IMPLICIT_PARTITIONS:
                reply = _query_implicit_partitions(self.rows, self.columns)

            if reply is not None:
                replies.append((code, reply))

        if request_type == QueryListRequestType.LIST and not replies:
            replies.append((QueryCode.NULL, None))

        # Generate the summary reply.
        structured_fields = [(StructuredField.QUERY_REPLY, bytes([QueryCode.SUMMARY, QueryCode.SUMMARY] + [code for (code, _) in replies]))]

        # Append the query replies.
        for (code, data) in replies:
            structured_fields.append((StructuredField.QUERY_REPLY, bytes([code]) + (data if data is not None else bytes([]))))

        bytes_ = format_inbound_structured_fields(structured_fields)

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f'\tData = {bytes_}')

        self.stream.write(bytes_)

def _query_usable_area(rows, columns):
    return struct.pack('>BBHHBHHHHBBH',
        0x01,           # 12/14-bit addressing allowed
        0x00,           # Cell units, no special features
        columns,        # Width in cells
        rows,           # Width in rows
        0x01,           # Millimeters
        10,             # X resolution fraction numerator
        741,            # X resolution fraction denominator
        2,              # Y resolution fraction numerator
        111,            # Y resolution fraction denominator
        9,              # Width of cell in millimeters
        12,             # Height of cell in millimeters
        rows * columns  # Buffer size
    )

def _query_alphanumeric_partitions(rows, columns):
    return struct.pack('>BHB',
        1,              # One partition
        rows * columns, # Buffer size
        0x00            # No special features
    )

def _query_reply_modes():
    return struct.pack('>B',
        0x00            # Field mode
    )

def _query_implicit_partitions(rows, columns):
    return struct.pack('>HBBBHHHH',
        0x0000,         # Flags
        0x0b,           # Length
        0x01,           # Size
        0x00,           # Flags
        80,             # Width
        24,             # Height
        columns,        # Width
        rows            # Height
    )
