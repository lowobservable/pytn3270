"""
tn3270.telnet
~~~~~~~~~~~~~
"""

from enum import IntEnum
from collections import namedtuple
import struct
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

# https://tools.ietf.org/html/rfc2355
RFC2355_CONNECT = b'\x01'
RFC2355_DEVICE_TYPE = b'\x02'
RFC2355_FUNCTIONS = b'\x03'
RFC2355_IS = b'\x04'
RFC2355_REJECT = b'\x06'
RFC2355_REQUEST = b'\x07'
RFC2355_SEND = b'\x08'

TN3270EMessageHeader = namedtuple('TN3270EMessageHeader', ['data_type', 'request_flag', 'response_flag', 'sequence_number'])

class TN3270EFunction(IntEnum):
    BIND_IMAGE = 0x00
    DATA_STREAM_CTL = 0x01
    RESPONSES = 0x02
    SCS_CTL_CODES = 0x03
    SYSREQ = 0x04

class TN3270EDataType(IntEnum):
    DATA_3270 = 0x00
    DATA_SCS = 0x01
    RESPONSE = 0x02
    BIND_IMAGE = 0x03
    UNBIND = 0x04
    DATA_NVT = 0x05
    REQUEST = 0x06
    DATA_SSCP_LU = 0x07
    PRINT_EOJ = 0x08

class TN3270ERequestFlag(IntEnum):
    ERROR_CONDITION_CLEARED = 0x00

class TN3270EResponseFlag(IntEnum):
    NO = 0x00
    ERROR = 0x01
    ALWAYS = 0x02

class Telnet:
    """TN3270 client."""

    def __init__(self, terminal_type, is_tn3270e_enabled=True, tn3270e_functions=None):
        self.logger = logging.getLogger(__name__)

        self.terminal_type = terminal_type
        self.is_tn3270e_enabled = is_tn3270e_enabled

        if tn3270e_functions is not None and not is_tn3270e_enabled:
            raise ValueError('TN3270E functions not valid if TN3270E is not enabled')

        self.requested_tn3270e_functions = set(tn3270e_functions if tn3270e_functions is not None else [])

        self.socket = None
        self.socket_selector = None
        self.eof = None

        self.device_names = None
        self.host_options = set()
        self.client_options = set()
        self.is_tn3270e_negotiated = False
        self.device_type = None
        self.device_name = None
        self.tn3270e_functions = set()

        self.buffer = bytearray()
        self.iac_buffer = bytearray()
        self.records = []
        self.device_names_stack = None

    def open(self, host, port, device_names=None, tn3270_negotiation_timeout=None, ssl_context=None, ssl_server_hostname=None):
        """Open the connection."""
        self.close()

        self.socket = socket.create_connection((host, port))

        if ssl_context:
            self.socket = ssl_context.wrap_socket(self.socket, server_hostname=ssl_server_hostname)

        self.socket_selector = selectors.DefaultSelector()

        self.socket_selector.register(self.socket, selectors.EVENT_READ)

        self.eof = False

        self.device_names = device_names
        self.host_options = set()
        self.client_options = set()
        self.is_tn3270e_negotiated = False
        self.device_type = None
        self.device_name = None
        self.tn3270e_functions = set()

        self.buffer = bytearray()
        self.iac_buffer = bytearray()
        self.records = []
        self.device_names_stack = None

        self._negotiate_tn3270(timeout=tn3270_negotiation_timeout)

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

    def write(self, record):
        """Write a record."""

        # Add 3270-DATA TN3270E header if in TN3270E mode.
        if self.is_tn3270e_negotiated:
            record = bytes([0x00, 0x00, 0x00, 0x00, 0x00]) + record

        self.socket.sendall(record.replace(IAC, IAC * 2) + IAC + RFC855_EOR)

    def send_tn3270e_positive_response(self, sequence_number):
        """Send a TN3270E positive response message."""
        if not self.is_tn3270e_negotiated:
            raise Exception('TN3270E mode not negotiated')

        if TN3270EFunction.RESPONSES not in self.tn3270e_functions:
            raise Exception('TN3270E responses not negotiated')

        self.logger.debug(f'Sending TN3270E positive response for {sequence_number}')

        bytes_ = struct.pack('!H', sequence_number)

        self.socket.sendall(b'\x02\x00\x00' + bytes_.replace(IAC, IAC * 2) + b'\x00' + IAC + RFC855_EOR)

    def send_tn3270e_negative_response(self, sequence_number, reason):
        """Send a TN3270E negative response message."""
        if not self.is_tn3270e_negotiated:
            raise Exception('TN3270E mode not negotiated')

        if TN3270EFunction.RESPONSES not in self.tn3270e_functions:
            raise Exception('TN3270E responses not negotiated')

        self.logger.debug(f'Sending TN3270E negative response for {sequence_number}, reason = {reason}')

        bytes_ = struct.pack('!HB', sequence_number, reason)

        self.socket.sendall(b'\x02\x00\x01' + bytes_.replace(IAC, IAC * 2) + IAC + RFC855_EOR)

    @property
    def is_tn3270_negotiated(self):
        """Has TN3270 or TN3270E mode been negotiated."""

        if self.is_tn3270e_negotiated:
            return True

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

                    self._handle_subnegotiation(self.iac_buffer[2:-1].replace(IAC * 2, IAC))

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
            if option in [BINARY, EOR, TTYPE] or (option == TN3270E and self.is_tn3270e_enabled):
                self.host_options.add(option)

                self.socket.sendall(IAC + DO + option)
            else:
                self.socket.sendall(IAC + DONT + option)
        elif command == WONT:
            self.host_options.discard(option)

            self.socket.sendall(IAC + DONT + option)
        elif command == DO:
            if option in [BINARY, EOR, TTYPE] or (option == TN3270E and self.is_tn3270e_enabled):
                self.client_options.add(option)

                self.socket.sendall(IAC + WILL + option)
            else:
                self.socket.sendall(IAC + WONT + option)
        elif command == DONT:
            self.client_options.discard(option)

            self.socket.sendall(IAC + WONT + option)

    def _handle_subnegotiation(self, bytes_):
        if bytes_ == TTYPE + RFC1091_SEND:
            self.logger.debug('Received TTYPE SEND request')

            # TN3270E and TTYPE negotation are supposed to be mutually exclusive.
            if self.is_tn3270e_negotiated:
                self.logger.warning('Unexpected TTYPE SEND request after TN3270E negotation')

            self.device_name = None

            if self.device_names_stack:
                self.device_name = self.device_names_stack.pop(0)

                self.logger.debug(f'Trying device name {self.device_name}...')
            elif self.device_names_stack is not None:
                self.logger.debug('Exhausted device names, continuing with no device name')

            terminal_type = encode_rfc1646_terminal_type(self.terminal_type, self.device_name)

            self.socket.sendall(IAC + SB + TTYPE + RFC1091_IS + terminal_type + IAC + SE)
        elif bytes_.startswith(TN3270E):
            if not self.is_tn3270e_enabled:
                self.logger.warning('TN3270E subnegotiation requested but TN3270E not enabled')

            self._handle_tn3270e_subnegotiation(bytes_[1:])

    def _handle_tn3270e_subnegotiation(self, bytes_):
        # TN3270E and TTYPE negotation are supposed to be mutually exclusive.
        if TTYPE in self.client_options:
            self.logger.warning('Unexpected TN3270E negotiation after TTYPE')

        if bytes_ == RFC2355_SEND + RFC2355_DEVICE_TYPE:
            self.logger.debug('Received TN3270E SEND DEVICE-TYPE request')

            self._send_tn3270e_device_type()
        elif bytes_.startswith(RFC2355_DEVICE_TYPE + RFC2355_IS):
            self.logger.debug('Received TN3270E DEVICE-TYPE response')

            (self.device_type, self.device_name) = decode_rfc2355_device_type(bytes_[2:])

            self._send_tn3270e_functions(RFC2355_REQUEST, self.requested_tn3270e_functions)
        elif bytes_.startswith(RFC2355_DEVICE_TYPE + RFC2355_REJECT):
            self.logger.debug('Received TN3270E DEVICE-TYPE REJECT response')

            self.device_name = None

            # Try the next device name, or reset the stack for TTYPE negotation.
            if self.device_names_stack:
                self._send_tn3270e_device_type()
            else:
                if self.device_names_stack is not None:
                    self.logger.debug('Exhausted device names, continuing without TN3270E')
                else:
                    self.logger.debug('Continuing without TN3270E')

                self._reset_device_names_stack()

                self.socket.sendall(IAC + WONT + TN3270E)
        elif bytes_.startswith(RFC2355_FUNCTIONS + RFC2355_REQUEST):
            self.logger.debug('Received TN3270E FUNCTIONS request')

            functions = set([TN3270EFunction(byte_) for byte_ in bytes_[2:]])

            if functions.issubset(self.requested_tn3270e_functions):
                self.tn3270e_functions = functions

                self._send_tn3270e_functions(RFC2355_IS, functions)

                self.logger.debug('TN3270E negotiation complete')

                self.is_tn3270e_negotiated = True
            else:
                common_functions = functions.intersection(self.requested_tn3270e_functions)

                self._send_tn3270e_functions(RFC2355_REQUEST, common_functions)
        elif bytes_.startswith(RFC2355_FUNCTIONS + RFC2355_IS):
            self.logger.debug('Received TN3270E FUNCTIONS response')

            functions = set([TN3270EFunction(byte_) for byte_ in bytes_[2:]])

            if functions.issubset(self.requested_tn3270e_functions):
                self.tn3270e_functions = functions

                self._send_tn3270e_functions(RFC2355_IS, functions)

                self.logger.debug('TN3270E negotiation complete')

                self.is_tn3270e_negotiated = True
            else:
                self.logger.warning('TN3270E FUNCTIONS response contains unrequested functions, aborting TN3270E negotiation')

                self.socket.sendall(IAC + WONT + TN3270E)

    def _reset_device_names_stack(self):
        # Clone the device names as the stack will be mutated during negotiation.
        self.device_names_stack = list(self.device_names) if self.device_names is not None else None

    def _send_tn3270e_device_type(self):
        device_type = self.terminal_type.replace('IBM-3279', 'IBM-3278')

        self.device_name = None

        if self.device_names_stack:
            self.device_name = self.device_names_stack.pop(0)

            self.logger.debug(f'Trying device name {self.device_name}...')

        bytes_ = encode_rfc2355_device_type(device_type, self.device_name)

        self.socket.sendall(IAC + SB + TN3270E + RFC2355_DEVICE_TYPE + RFC2355_REQUEST + bytes_ + IAC + SE)

    def _send_tn3270e_functions(self, command, functions):
        bytes_ = bytes(functions)

        self.socket.sendall(IAC + SB + TN3270E + RFC2355_FUNCTIONS + command + bytes_ + IAC + SE)

    def _negotiate_tn3270(self, timeout):
        self._reset_device_names_stack()

        self._read_while(lambda: not self.is_tn3270_negotiated and not self.eof
                         and not self.buffer, timeout)

        if not self.is_tn3270_negotiated:
            raise Exception('Unable to negotiate TN3270 mode')

    def _eor(self, record):
        self.logger.debug('Received EOR')

        if self.is_tn3270e_negotiated:
            header = decode_tn3270e_message_header(record[:5])
            data = record[5:]

            self.records.append((data, header))
        else:
            self.records.append((record, None))

    def __del__(self):
        self.close()

def encode_rfc1646_terminal_type(terminal_type, device_name):
    bytes_ = terminal_type.encode('ascii')

    if device_name is not None:
        bytes_ += f'@{device_name}'.encode('ascii')

    return bytes_

def encode_rfc2355_device_type(device_type, device_name):
    bytes_ = device_type.encode('ascii')

    if device_name is not None:
        bytes_ += RFC2355_CONNECT + device_name.encode('ascii')

    return bytes_

def decode_rfc2355_device_type(bytes_):
    elements = bytes_.split(RFC2355_CONNECT, 1)

    device_type = elements[0].decode('ascii')
    device_name = elements[1].decode('ascii') if len(elements) > 1 else None

    return (device_type, device_name)

def decode_tn3270e_message_header(bytes_):
    (data_type, request_flag, response_flag, sequence_number) = struct.unpack('!BBBH', bytes_)

    data_type = TN3270EDataType(data_type)

    request_flag = TN3270ERequestFlag(request_flag) if data_type == TN3270EDataType.REQUEST else None

    response_flag = TN3270EResponseFlag(response_flag) if data_type in (TN3270EDataType.DATA_3270, TN3270EDataType.DATA_SCS) else None

    return TN3270EMessageHeader(data_type, request_flag, response_flag, sequence_number)
