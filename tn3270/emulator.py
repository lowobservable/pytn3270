"""
tn3270.emulator
~~~~~~~~~~~~~~~
"""

from itertools import chain
import logging

from .datastream import Command, Order, AID, parse_outbound_message, \
                        format_inbound_read_buffer_message, \
                        format_inbound_read_modified_message
from .ebcdic import DUP, FM

class Cell:
    """A display cell."""

class AttributeCell(Cell):
    """A attribute display cell."""

    def __init__(self, attribute):
        self.attribute = attribute

class CharacterCell(Cell):
    """A character display cell."""

    def __init__(self, byte):
        self.byte = byte

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

        # TODO: Validate that stream has read() and write() methods.
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
        """Read a outbound message and execute command."""
        bytes_ = self.stream.read(**kwargs)

        if bytes_ is None:
            return False

        (command, *options) = parse_outbound_message(bytes_)

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('Update')
            self.logger.debug(f'\tData    = {bytes_}')
            self.logger.debug(f'\tCommand = {command}')

        if command == Command.W:
            self._write(*options)
        elif command == Command.RB:
            self._read_buffer()
        elif command == Command.NOP:
            pass
        elif command == Command.EW:
            self._erase()
            self._write(*options)
        elif command == Command.RM:
            self._read_modified()
        elif command == Command.EWA:
            raise NotImplementedError('EWA command is not supported')
        elif command == Command.RMA:
            self._read_modified(all_=True)
        elif command == Command.EAU:
            self._erase_all_unprotected()
        elif command == Command.WSF:
            raise NotImplementedError('WSF command is not supported')

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
            self._write_character(address, 0x00)

        attribute.modified = True

    def erase_input(self):
        """Erase input key."""
        for (start_address, end_address, attribute) in self.get_fields():
            for address in self._get_addresses(start_address, end_address):
                self._write_character(address, 0x00)

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

    def _erase(self):
        self.logger.debug('Erase')

        self._clear()

    def _erase_all_unprotected(self):
        self.logger.debug('Erase All Unprotected')

        for (start_address, end_address, attribute) in self.get_fields():
            for address in self._get_addresses(start_address, end_address):
                self._write_character(address, 0x00)

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

        for (order, data) in orders:
            if self.logger.isEnabledFor(logging.DEBUG):
                if order is None:
                    self.logger.debug(f'\t{data}')
                else:
                    self.logger.debug(f'\t{order}')
                    self.logger.debug(f'\t\tParameters = {data}')

            if order == Order.PT:
                # TODO: PT is more complex to implement that simply duplicating the
                # behavior of tab() - how it behaves differs based on what command it
                # follows.
                raise NotImplementedError('PT order is not supported')
            elif order == Order.GE:
                raise NotImplementedError('GE order is not supported')
            elif order == Order.SBA:
                self.address = data[0]
            elif order == Order.EUA:
                stop_address = data[0]

                # TODO: Validate stop_address is in range...
                end_address = self._wrap_address(stop_address - 1)

                addresses = self._get_addresses(self.address, end_address)
                unprotected_addresses = self._get_unprotected_addresses()

                for address in unprotected_addresses.intersection(addresses):
                    self._write_character(address, 0x00)

                self.address = stop_address
            elif order == Order.IC:
                self.cursor_address = self.address
            elif order == Order.SF:
                self._write_attribute(self.address, data[0])

                self.address += 1
            elif order == Order.SA:
                raise NotImplementedError('SA order is not supported')
            elif order == Order.SFE:
                raise NotImplementedError('SFE order is not supported')
            elif order == Order.MF:
                raise NotImplementedError('MF order is not supported')
            elif order == Order.RA:
                (stop_address, byte) = data

                # TODO: Validate stop_address is in range...
                end_address = self._wrap_address(stop_address - 1)

                addresses = self._get_addresses(self.address, end_address)

                for address in addresses:
                    self._write_character(address, byte)

                self.address = stop_address
            elif order is None:
                for byte in data:
                    self._write_character(self.address, byte)

                    self.address += 1

        if wcc.unlock_keyboard:
            self.current_aid = AID.NONE
            self.keyboard_locked = False

        if wcc.alarm:
            self.alarm()

    def _clear(self):
        for address in range(self.rows * self.columns):
            self._write_character(address, 0x00)

        self.address = 0
        self.cursor_address = 0

    def _read_buffer(self):
        orders = []

        data = bytearray()

        for cell in self.cells:
            if isinstance(cell, AttributeCell):
                if data:
                    orders.append((None, data))

                    data = bytearray()

                orders.append((Order.SF, [cell.attribute]))
            elif isinstance(cell, CharacterCell):
                data.append(cell.byte)

        if data:
            orders.append((None, data))

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('Read Buffer')
            self.logger.debug(f'\tAID    = {self.current_aid}')

        bytes_ = format_inbound_read_buffer_message(self.current_aid, self.cursor_address, orders)

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f'\tData   = {bytes_}')

        self.stream.write(bytes_)

    def _read_modified(self, all_=False):
        modified_field_ranges = [(start_address, end_address) for (start_address, end_address, attribute) in self.get_fields() if attribute.modified]

        fields = [(start_address, self.get_bytes(start_address, end_address)) for (start_address, end_address) in modified_field_ranges]

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('Read Modified')
            self.logger.debug(f'\tAID    = {self.current_aid}')
            self.logger.debug(f'\tFields = {fields}')
            self.logger.debug(f'\tAll    = {all_}')

        bytes_ = format_inbound_read_modified_message(self.current_aid, self.cursor_address, fields, all_)

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

        self._write_character(self.cursor_address, byte)

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

    def _write_attribute(self, index, attribute):
        cell = self.cells[index]

        if isinstance(cell, AttributeCell):
            if cell.attribute.value == attribute.value:
                return False

            cell.attribute = attribute
        else:
            self.cells[index] = AttributeCell(attribute)

        self.dirty.add(index)

        return True

    def _write_character(self, index, byte):
        cell = self.cells[index]

        if isinstance(cell, CharacterCell):
            if cell.byte == byte:
                return False

            cell.byte = byte
        else:
            self.cells[index] = CharacterCell(byte)

        self.dirty.add(index)

        return True

    def _shift_left(self, start_address, end_address):
        addresses = list(self._get_addresses(start_address, end_address))

        for (left_address, right_address) in zip(addresses, addresses[1:]):
            self._write_character(left_address, self.cells[right_address].byte)

        self._write_character(end_address, 0x00)

    def _shift_right(self, start_address, end_address):
        addresses = list(self._get_addresses(start_address, end_address))

        for (left_address, right_address) in reversed(list(zip(addresses, addresses[1:]))):
            self._write_character(right_address, self.cells[left_address].byte)

        self._write_character(start_address, 0x00)
