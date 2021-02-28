import selectors
import unittest
from unittest.mock import Mock, patch

import context

from tn3270.telnet import Telnet

class OpenTestCase(unittest.TestCase):
    def setUp(self):
        self.telnet = Telnet('IBM-3278-2')

        self.socket_mock = Mock()

        self.socket_selector_mock = Mock()

        selector_key = Mock(fileobj=self.socket_mock)

        self.socket_selector_mock.select.return_value = [(selector_key, selectors.EVENT_READ)]

        patcher = patch('socket.create_connection')

        create_connection_mock = patcher.start()

        create_connection_mock.return_value = self.socket_mock

        patcher = patch('selectors.DefaultSelector')

        default_selector_mock = patcher.start()

        default_selector_mock.return_value = self.socket_selector_mock

        self.addCleanup(patch.stopall)

    def test_negotiation(self):
        # Arrange
        responses = [
            bytes.fromhex('ff fd 28'),
            bytes.fromhex('ff fd 18'),
            bytes.fromhex('ff fa 18 01 ff f0'),
            bytes.fromhex('ff fd 19'),
            bytes.fromhex('ff fb 19'),
            bytes.fromhex('ff fd 00'),
            bytes.fromhex('ff fb 00')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        self.assertFalse(self.telnet.is_3270)

        # Act
        self.telnet.open('mainframe', 23)

        # Assert
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fc 28'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fb 18'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fa 18 00 49 42 4d 2d 33 32 37 38 2d 32 ff f0'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fb 19'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fd 19'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fb 00'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fd 00'))

        self.assertTrue(self.telnet.is_3270)

    def test_unsuccessful_negotiation(self):
        # Arrange
        self.socket_mock.recv = Mock(return_value='hello world'.encode('ascii'))

        self.assertFalse(self.telnet.is_3270)

        # Act and assert
        with self.assertRaisesRegex(Exception, 'Unable to negotiate 3270 mode'):
            self.telnet.open('mainframe', 23)

class ReadMultipleTestCase(unittest.TestCase):
    def setUp(self):
        self.telnet = Telnet('IBM-3278-2')

        self.telnet.socket = Mock()

        self.telnet.socket_selector = Mock()

        selector_key = Mock(fileobj=self.telnet.socket)

        self.telnet.socket_selector.select.return_value = [(selector_key, selectors.EVENT_READ)]

        self.addCleanup(patch.stopall)

    def test_multiple_records_in_single_recv(self):
        # Arrange
        self.telnet.socket.recv = Mock(return_value=bytes.fromhex('01 02 03 ff ef 04 05 06 ff ef'))

        # Act and assert
        self.assertEqual(self.telnet.read_multiple(), [bytes.fromhex('01 02 03'), bytes.fromhex('04 05 06')])

    def test_single_record_spans_multiple_recv(self):
        # Arrange
        self.telnet.socket.recv = Mock(side_effect=[bytes.fromhex('01 02 03'), bytes.fromhex('04 05 06 ff ef')])

        # Act and assert
        self.assertEqual(self.telnet.read_multiple(), [bytes.fromhex('01 02 03 04 05 06')])

    def test_limit(self):
        # Arrange
        self.telnet.socket.recv = Mock(return_value=bytes.fromhex('01 02 03 ff ef 04 05 06 ff ef'))

        # Act and assert
        self.assertEqual(self.telnet.read_multiple(limit=1), [bytes.fromhex('01 02 03')])

    def test_timeout(self):
        # Arrange
        self.telnet.socket.recv = Mock(side_effect=[bytes.fromhex('01 02 03')])

        selector_key = Mock(fileobj=self.telnet.socket)

        self.telnet.socket_selector.select.side_effect = [[(selector_key, selectors.EVENT_READ)], []]

        # Act and assert
        with patch('time.perf_counter') as perf_counter_mock:
            perf_counter_mock.side_effect=[1, 3, 3, 7]

            self.telnet.read_multiple(timeout=5)

            self.assertEqual(self.telnet.socket_selector.select.call_count, 2)

            mock_calls = self.telnet.socket_selector.select.mock_calls

            self.assertEqual(mock_calls[0][1][0], 5)
            self.assertEqual(mock_calls[1][1][0], 3)

    def test_recv_eof(self):
        # Arrange
        self.telnet.socket.recv = Mock(return_value=b'')

        self.assertFalse(self.telnet.eof)

        # Act and assert
        with self.assertRaises(EOFError):
            self.telnet.read_multiple()

        self.assertTrue(self.telnet.eof)

class WriteTestCase(unittest.TestCase):
    def test(self):
        # Arrange
        telnet = Telnet('IBM-3278-2')

        telnet.socket = Mock()

        # Act
        telnet.write(bytes.fromhex('01 02 03 ff 04 05'))

        # Assert
        telnet.socket.sendall.assert_called_with(bytes.fromhex('01 02 03 ff ff 04 05 ff ef'))
