"""
tn3270.telnet
~~~~~~~~~~~~~
"""

import time
import logging
import socket
import selectors
from telnetlib import IAC, WILL, WONT, DO, DONT, SB, SE, BINARY, EOR, TTYPE, TN3270E

# https://tools.ietf.org/html/rfc855
RFC855_EOR = b'\xef'

# https://tools.ietf.org/html/rfc1091
RFC1091_IS = b'\x00'
RFC1091_SEND = b'\x01'

class Telnet:
    """TN3270 client."""

    def __init__(self, terminal_type):
        self.logger = logging.getLogger(__name__)

        self.terminal_type = terminal_type

        self.socket = None
        self.socket_selector = None
        self.eof = None

        self.host_options = set()
        self.client_options = set()

        self.buffer = bytearray()
        self.iac_buffer = bytearray()
        self.records = []

    def open(self, host, port):
        """Open the connection."""
        self.close()

        self.socket = socket.create_connection((host, port))

        self.socket_selector = selectors.DefaultSelector()

        self.socket_selector.register(self.socket, selectors.EVENT_READ)

        self.eof = False

        self.host_options = set()
        self.client_options = set()

        self.buffer = bytearray()
        self.iac_buffer = bytearray()
        self.records = []

        self._negotiate_3270(timeout=None)

    def close(self):
        """Close the connection."""
        if self.socket_selector is not None:
            self.socket_selector.unregister(self.socket)

        if self.socket is not None:
            self.socket.close()

            self.socket = None

        if self.socket_selector is not None:
            self.socket_selector.close()

            self.socket_selector = None

    def read_multiple(self, limit=None, timeout=None):
        """Read multiple records."""
        records = self._read_multiple_buffered(limit)

        if records:
            return records

        self._read_while(lambda: not self.eof and not self.records, timeout)

        # TODO: Determine what happens to any bytes in the buffer if EOF is
        # encountered without EOR - should that yield a record?
        if self.eof and self.buffer:
            self.logger.warning('EOF encountered with partial record')

        return self._read_multiple_buffered(limit)

    def write(self, frame):
        """Write a record."""
        self.socket.sendall(frame.replace(IAC, IAC * 2) + IAC + RFC855_EOR)

    @property
    def is_3270(self):
        """Is in 3270 mode."""

        # https://tools.ietf.org/html/rfc1576
        return (self.client_options.issuperset([BINARY, EOR, TTYPE])
                and self.host_options.issuperset([BINARY, EOR]))

    def _read(self, timeout):
        if self.eof:
            raise EOFError

        if not self.socket_selector.select(timeout):
            return

        bytes_ = self.socket.recv(1024)

        if not bytes_:
            self.eof = True
            return

        for byte in bytes_:
            self._feed(bytes([byte]))

    def _read_while(self, predicate, timeout):
        remaining_timeout = timeout

        while predicate():
            read_time = time.perf_counter()

            self._read(remaining_timeout)

            if remaining_timeout is not None:
                remaining_timeout -= (time.perf_counter() - read_time)

                if remaining_timeout < 0:
                    break

    def _read_multiple_buffered(self, limit=None):
        if self.eof and not self.records:
            raise EOFError

        if not self.records:
            return []

        count = limit if limit is not None else len(self.records)

        records = self.records[:count]

        self.records = self.records[count:]

        return records

    def _feed(self, byte):
        if not self.iac_buffer:
            if byte == IAC:
                self.iac_buffer += byte
                return

            self.buffer += byte
        elif len(self.iac_buffer) == 1:
            if byte == IAC:
                self.buffer += IAC
                self.iac_buffer.clear()
                return

            if byte == RFC855_EOR:
                self._eor(bytearray(self.buffer))

                self.buffer.clear()
                self.iac_buffer.clear()
                return

            if byte in [WILL, WONT, DO, DONT, SB]:
                self.iac_buffer += byte
                return

            self.logger.warning(f'Unexpected byte 0x{byte[0]:02x} in IAC state')

            self.iac_buffer.clear()
        elif len(self.iac_buffer) > 1:
            command = self.iac_buffer[1:2]

            if command in [WILL, WONT, DO, DONT]:
                self._handle_negotiation(command, byte)

                self.iac_buffer.clear()
                return

            if command == SB:
                if byte == SE:
                    if self.iac_buffer[-1:] != IAC:
                        self.logger.warning('Expected IAC prior to SE')

                    self._handle_subnegotation(self.iac_buffer[2:-1].replace(IAC * 2, IAC))

                    self.iac_buffer.clear()
                    return

                self.iac_buffer += byte
                return

            self.logger.warning(f'Unrecognized command 0x{command:02x}')

            self.iac_buffer.clear()

    def _handle_negotiation(self, command, option):
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug((f'Negotiate: Command = 0x{command.hex()}, '
                               f'Option = 0x{option.hex()}'))

        if command == WILL:
            if option in [BINARY, EOR, TTYPE]:
                if option not in self.host_options:
                    self.host_options.add(option)

                    self.socket.sendall(IAC + DO + option)
            else:
                if option == TN3270E:
                    self.logger.info('WILL TN3270E requested... currently not supported')

                self.socket.sendall(IAC + DONT + option)
        elif command == WONT:
            if option in self.host_options:
                self.host_options.remove(option)

                self.socket.sendall(IAC + DONT + option)
        elif command == DO:
            if option in [BINARY, EOR, TTYPE]:
                if option not in self.client_options:
                    self.client_options.add(option)

                    self.socket.sendall(IAC + WILL + option)
            else:
                if option == TN3270E:
                    self.logger.info('DO TN3270E requested... currently not supported')

                self.socket.sendall(IAC + WONT + option)
        elif command == DONT:
            if option in self.client_options:
                self.client_options.remove(option)

                self.socket.sendall(IAC + WONT + option)

    def _handle_subnegotation(self, bytes_):
        if bytes_ == TTYPE + RFC1091_SEND:
            self.logger.debug('Received TTYPE SEND request')

            terminal_type = self.terminal_type.encode('ascii')

            self.socket.sendall(IAC + SB + TTYPE + RFC1091_IS + terminal_type + IAC + SE)

    def _negotiate_3270(self, timeout):
        self._read_while(lambda: not self.is_3270 and not self.eof and not self.buffer,
                         timeout)

        if not self.is_3270:
            raise Exception('Unable to negotiate 3270 mode')

    def _eor(self, record):
        self.logger.debug('Received EOR')

        self.records.append(record)

    def __del__(self):
        self.close()
