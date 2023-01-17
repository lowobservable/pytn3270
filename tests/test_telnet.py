import unittest
from unittest.mock import Mock, create_autospec, patch

from socket import socket
import selectors
from selectors import BaseSelector
import ssl

from tn3270.telnet import Telnet, TN3270EFunction, TN3270EMessageHeader, TN3270EDataType, TN3270EResponseFlag, encode_rfc1646_terminal_type, encode_rfc2355_device_type, decode_rfc2355_device_type

class OpenTestCase(unittest.TestCase):
    def setUp(self):
        self.socket_mock = create_autospec(socket, instance=True)

        self.socket_selector_mock = create_autospec(BaseSelector, instance=True)

        selector_key = Mock(fileobj=self.socket_mock)

        self.socket_selector_mock.select.return_value = [(selector_key, selectors.EVENT_READ)]

        patcher = patch('socket.create_connection')

        create_connection_mock = patcher.start()

        create_connection_mock.return_value = self.socket_mock

        patcher = patch('selectors.DefaultSelector')

        default_selector_mock = patcher.start()

        default_selector_mock.return_value = self.socket_selector_mock

        patcher = patch('ssl.SSLContext.wrap_socket')

        ssl_wrap_socket_mock = patcher.start()

        ssl_wrap_socket_mock.return_value = self.socket_mock

        self.addCleanup(patch.stopall)

    def test_init(self):
        # Act
        self.telnet = Telnet('IBM-3279-2-E')

        # Assert
        self.assertFalse(self.telnet.is_tn3270_negotiated)
        self.assertFalse(self.telnet.is_tn3270e_negotiated)

    def test_basic_tn3270_negotiation(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E')

        responses = [
            bytes.fromhex('ff fd 18'),
            bytes.fromhex('ff fa 18 01 ff f0'),
            bytes.fromhex('ff fd 19'),
            bytes.fromhex('ff fb 19'),
            bytes.fromhex('ff fd 00'),
            bytes.fromhex('ff fb 00')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        self.telnet.open('mainframe', 23)

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertFalse(self.telnet.is_tn3270e_negotiated)

        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fb 18'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fa 18 00 49 42 4d 2d 33 32 37 39 2d 32 2d 45 ff f0'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fb 19'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fd 19'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fb 00'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fd 00'))

    def test_tn3270e_negotiation(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E')

        responses = [
            bytes.fromhex('ff fd 28'),
            bytes.fromhex('ff fa 28 08 02 ff f0'),
            bytes.fromhex('ff fa 28 02 04 49 42 4d 2d 33 32 37 38 2d 32 2d 45 01 54 43 50 30 30 30 33 34 ff f0'),
            bytes.fromhex('ff fa 28 03 04 ff f0')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        self.telnet.open('mainframe', 23)

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertTrue(self.telnet.is_tn3270e_negotiated)

        self.assertEqual(self.telnet.device_type, 'IBM-3278-2-E')
        self.assertEqual(self.telnet.device_name, 'TCP00034')

        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fb 28'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fa 28 02 07 49 42 4d 2d 33 32 37 38 2d 32 2d 45 ff f0'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fa 28 03 07 ff f0'))

    def test_basic_tn3270_negotiation_when_tn3270e_not_enabled(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E', is_tn3270e_enabled=False)

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

        # Act
        self.telnet.open('mainframe', 23)

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertFalse(self.telnet.is_tn3270e_negotiated)

        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fc 28'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fb 18'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fa 18 00 49 42 4d 2d 33 32 37 39 2d 32 2d 45 ff f0'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fb 19'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fd 19'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fb 00'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fd 00'))

    def test_unsuccessful_negotiation(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E')

        self.socket_mock.recv = Mock(return_value='hello world'.encode('ascii'))

        # Act and assert
        with self.assertRaisesRegex(Exception, 'Unable to negotiate TN3270 mode'):
            self.telnet.open('mainframe', 23)

    def test_tn3270e_negotiation_ssl(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E')

        responses = [
            bytes.fromhex('ff fd 28'),
            bytes.fromhex('ff fa 28 08 02 ff f0'),
            bytes.fromhex('ff fa 28 02 04 49 42 4d 2d 33 32 37 38 2d 32 2d 45 01 54 43 50 30 30 30 33 34 ff f0'),
            bytes.fromhex('ff fa 28 03 04 ff f0')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        ssl_context = ssl.create_default_context()
        self.telnet.open('mainframe', 23, ssl_context=ssl_context)

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertTrue(self.telnet.is_tn3270e_negotiated)

        self.assertEqual(self.telnet.device_type, 'IBM-3278-2-E')
        self.assertEqual(self.telnet.device_name, 'TCP00034')

        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fb 28'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fa 28 02 07 49 42 4d 2d 33 32 37 38 2d 32 2d 45 ff f0'))
        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fa 28 03 07 ff f0'))

    def test_tn3270_device_name_negotiation(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E')

        responses = [
            bytes.fromhex('ff fd 18'),
            bytes.fromhex('ff fa 18 01 ff f0'),
            bytes.fromhex('ff fd 19'),
            bytes.fromhex('ff fb 19'),
            bytes.fromhex('ff fd 00'),
            bytes.fromhex('ff fb 00')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        self.telnet.open('mainframe', 23, ['LU1'])

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertFalse(self.telnet.is_tn3270e_negotiated)

        self.assertEqual(self.telnet.device_name, 'LU1')

    def test_tn3270_device_name_negotiation_second_device(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E')

        responses = [
            bytes.fromhex('ff fd 18'),
            bytes.fromhex('ff fa 18 01 ff f0'),
            bytes.fromhex('ff fa 18 01 ff f0'),
            bytes.fromhex('ff fd 19'),
            bytes.fromhex('ff fb 19'),
            bytes.fromhex('ff fd 00'),
            bytes.fromhex('ff fb 00')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        self.telnet.open('mainframe', 23, ['LU1', 'LU2'])

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertFalse(self.telnet.is_tn3270e_negotiated)

        self.assertEqual(self.telnet.device_name, 'LU2')

    def test_tn3270_device_name_negotiation_exhausted(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E')

        responses = [
            bytes.fromhex('ff fd 18'),
            bytes.fromhex('ff fa 18 01 ff f0'),
            bytes.fromhex('ff fa 18 01 ff f0'),
            bytes.fromhex('ff fa 18 01 ff f0'),
            bytes.fromhex('ff fd 19'),
            bytes.fromhex('ff fb 19'),
            bytes.fromhex('ff fd 00'),
            bytes.fromhex('ff fb 00')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        self.telnet.open('mainframe', 23, ['LU1', 'LU2'])

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertFalse(self.telnet.is_tn3270e_negotiated)

        self.assertIsNone(self.telnet.device_name)

    def test_tn3270e_device_name_negotiation(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E')

        responses = [
            bytes.fromhex('ff fd 28'),
            bytes.fromhex('ff fa 28 08 02 ff f0'),
            bytes.fromhex('ff fa 28 02 04 49 42 4d 2d 33 32 37 38 2d 32 2d 45 01 4c 55 31 ff f0'),
            bytes.fromhex('ff fa 28 03 04 ff f0')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        self.telnet.open('mainframe', 23, ['LU1'])

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertTrue(self.telnet.is_tn3270e_negotiated)

        self.assertEqual(self.telnet.device_name, 'LU1')

    def test_tn3270e_device_name_negotiation_second_device(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E')

        responses = [
            bytes.fromhex('ff fd 28'),
            bytes.fromhex('ff fa 28 08 02 ff f0'),
            bytes.fromhex('ff fa 28 02 06 03 ff f0'),
            bytes.fromhex('ff fa 28 02 04 49 42 4d 2d 33 32 37 38 2d 32 2d 45 01 4c 55 32 ff f0'),
            bytes.fromhex('ff fa 28 03 04 ff f0')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        self.telnet.open('mainframe', 23, ['LU1', 'LU2'])

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertTrue(self.telnet.is_tn3270e_negotiated)

        self.assertEqual(self.telnet.device_name, 'LU2')

    def test_device_name_negotiation_exhausted(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E')

        responses = [
            bytes.fromhex('ff fd 28'),
            bytes.fromhex('ff fa 28 08 02 ff f0'),
            bytes.fromhex('ff fa 28 02 06 03 ff f0'),
            bytes.fromhex('ff fa 28 02 06 03 ff f0'),
            bytes.fromhex('ff fd 18'),
            bytes.fromhex('ff fa 18 01 ff f0'),
            bytes.fromhex('ff fa 18 01 ff f0'),
            bytes.fromhex('ff fa 18 01 ff f0'),
            bytes.fromhex('ff fd 19'),
            bytes.fromhex('ff fb 19'),
            bytes.fromhex('ff fd 00'),
            bytes.fromhex('ff fb 00')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        self.telnet.open('mainframe', 23, ['LU1', 'LU2'])

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertFalse(self.telnet.is_tn3270e_negotiated)

        self.assertIsNone(self.telnet.device_name)

    def test_tn3270e_function_negotiation_basic(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E', tn3270e_functions=[])

        responses = [
            bytes.fromhex('ff fd 28'),
            bytes.fromhex('ff fa 28 08 02 ff f0'),
            bytes.fromhex('ff fa 28 02 04 49 42 4d 2d 33 32 37 38 2d 32 2d 45 01 54 43 50 30 30 30 33 34 ff f0'),
            bytes.fromhex('ff fa 28 03 04 ff f0')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        self.telnet.open('mainframe', 23)

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertTrue(self.telnet.is_tn3270e_negotiated)

        self.assertSetEqual(self.telnet.tn3270e_functions, set([]))

        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fa 28 03 07 ff f0'))

    def test_tn3270e_function_negotiation_equal(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E', tn3270e_functions=[TN3270EFunction.BIND_IMAGE, TN3270EFunction.RESPONSES, TN3270EFunction.SYSREQ])

        responses = [
            bytes.fromhex('ff fd 28'),
            bytes.fromhex('ff fa 28 08 02 ff f0'),
            bytes.fromhex('ff fa 28 02 04 49 42 4d 2d 33 32 37 38 2d 32 2d 45 01 54 43 50 30 30 30 33 34 ff f0'),
            bytes.fromhex('ff fa 28 03 04 00 02 04 ff f0')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        self.telnet.open('mainframe', 23)

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertTrue(self.telnet.is_tn3270e_negotiated)

        self.assertSetEqual(self.telnet.tn3270e_functions, set([TN3270EFunction.BIND_IMAGE, TN3270EFunction.RESPONSES, TN3270EFunction.SYSREQ]))

        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fa 28 03 07 00 02 04 ff f0'))

    def test_tn3270e_function_negotiation_subset(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E', tn3270e_functions=[TN3270EFunction.BIND_IMAGE, TN3270EFunction.RESPONSES, TN3270EFunction.SYSREQ])

        responses = [
            bytes.fromhex('ff fd 28'),
            bytes.fromhex('ff fa 28 08 02 ff f0'),
            bytes.fromhex('ff fa 28 02 04 49 42 4d 2d 33 32 37 38 2d 32 2d 45 01 54 43 50 30 30 30 33 34 ff f0'),
            bytes.fromhex('ff fa 28 03 04 02 ff f0')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        self.telnet.open('mainframe', 23)

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertTrue(self.telnet.is_tn3270e_negotiated)

        self.assertSetEqual(self.telnet.tn3270e_functions, set([TN3270EFunction.RESPONSES]))

        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fa 28 03 07 00 02 04 ff f0'))

    def test_tn3270e_function_negotiation_common(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E', tn3270e_functions=[TN3270EFunction.RESPONSES])

        responses = [
            bytes.fromhex('ff fd 28'),
            bytes.fromhex('ff fa 28 08 02 ff f0'),
            bytes.fromhex('ff fa 28 02 04 49 42 4d 2d 33 32 37 38 2d 32 2d 45 01 54 43 50 30 30 30 33 34 ff f0'),
            bytes.fromhex('ff fa 28 03 07 00 02 04 ff f0'),
            bytes.fromhex('ff fa 28 03 04 02 ff f0')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        self.telnet.open('mainframe', 23)

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertTrue(self.telnet.is_tn3270e_negotiated)

        self.assertSetEqual(self.telnet.tn3270e_functions, set([TN3270EFunction.RESPONSES]))

        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fa 28 03 07 02 ff f0'))

    def test_tn3270e_function_negotiation_invalid(self):
        # Arrange
        self.telnet = Telnet('IBM-3279-2-E', tn3270e_functions=[TN3270EFunction.RESPONSES])

        responses = [
            bytes.fromhex('ff fd 28'),
            bytes.fromhex('ff fa 28 08 02 ff f0'),
            bytes.fromhex('ff fa 28 02 04 49 42 4d 2d 33 32 37 38 2d 32 2d 45 01 54 43 50 30 30 30 33 34 ff f0'),
            bytes.fromhex('ff fa 28 03 04 00 02 04 ff f0'),
            bytes.fromhex('ff fd 18'),
            bytes.fromhex('ff fa 18 01 ff f0'),
            bytes.fromhex('ff fd 19'),
            bytes.fromhex('ff fb 19'),
            bytes.fromhex('ff fd 00'),
            bytes.fromhex('ff fb 00')
        ]

        self.socket_mock.recv = Mock(side_effect=responses)

        # Act
        self.telnet.open('mainframe', 23)

        # Assert
        self.assertTrue(self.telnet.is_tn3270_negotiated)
        self.assertFalse(self.telnet.is_tn3270e_negotiated)

        self.assertSetEqual(self.telnet.tn3270e_functions, set([]))

        self.socket_mock.sendall.assert_any_call(bytes.fromhex('ff fc 28'))

class ReadMultipleTestCase(unittest.TestCase):
    def setUp(self):
        self.telnet = Telnet('IBM-3279-2-E')

        self.telnet.socket = create_autospec(socket, instance=True)

        self.telnet.socket_selector = create_autospec(BaseSelector, instance=True)

        self.is_tn3270e_negotiated = False

        selector_key = Mock(fileobj=self.telnet.socket)

        self.telnet.socket_selector.select.return_value = [(selector_key, selectors.EVENT_READ)]

    def test_multiple_records_in_single_recv(self):
        # Arrange
        self.telnet.socket.recv = Mock(return_value=bytes.fromhex('01 02 03 ff ef 04 05 06 ff ef'))

        # Act and assert
        self.assertEqual(self.telnet.read_multiple(), [(bytes.fromhex('01 02 03'), None), (bytes.fromhex('04 05 06'), None)])

    def test_single_record_spans_multiple_recv(self):
        # Arrange
        self.telnet.socket.recv = Mock(side_effect=[bytes.fromhex('01 02 03'), bytes.fromhex('04 05 06 ff ef')])

        # Act and assert
        self.assertEqual(self.telnet.read_multiple(), [(bytes.fromhex('01 02 03 04 05 06'), None)])

    def test_limit(self):
        # Arrange
        self.telnet.socket.recv = Mock(return_value=bytes.fromhex('01 02 03 ff ef 04 05 06 ff ef'))

        # Act and assert
        self.assertEqual(self.telnet.read_multiple(limit=1), [(bytes.fromhex('01 02 03'), None)])

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

    def test_tn3270e(self):
        # Arrange
        self.telnet.is_tn3270e_negotiated = True

        self.telnet.socket.recv = Mock(return_value=bytes.fromhex('00 00 00 00 00 01 02 03 ff ef'))

        # Act and assert
        self.assertEqual(self.telnet.read_multiple(), [(bytes.fromhex('01 02 03'), TN3270EMessageHeader(TN3270EDataType.DATA_3270, None, TN3270EResponseFlag.NO, 0))])

class WriteTestCase(unittest.TestCase):
    def test_basic_tn3270(self):
        # Arrange
        telnet = Telnet('IBM-3279-2-E')

        telnet.socket = create_autospec(socket, instance=True)

        telnet.is_tn3270e_negotiated = False

        # Act
        telnet.write(bytes.fromhex('01 02 03 ff 04 05'))

        # Assert
        telnet.socket.sendall.assert_called_with(bytes.fromhex('01 02 03 ff ff 04 05 ff ef'))

    def test_tn3270e(self):
        # Arrange
        telnet = Telnet('IBM-3279-2-E')

        telnet.socket = create_autospec(socket, instance=True)

        telnet.is_tn3270e_negotiated = True

        # Act
        telnet.write(bytes.fromhex('01 02 03 ff 04 05'))

        # Assert
        telnet.socket.sendall.assert_called_with(bytes.fromhex('00 00 00 00 00 01 02 03 ff ff 04 05 ff ef'))

class SendTN3270EPositiveResponse(unittest.TestCase):
    def test(self):
        # Arrange
        telnet = Telnet('IBM-3279-2-E')

        telnet.socket = create_autospec(socket, instance=True)

        telnet.is_tn3270e_negotiated = True
        telnet.tn3270e_functions = set([TN3270EFunction.RESPONSES])

        # Act
        telnet.send_tn3270e_positive_response(255)

        # Assert
        telnet.socket.sendall.assert_called_with(bytes.fromhex('02 00 00 00 ff ff 00 ff ef'))

    def test_tn3270e_not_negotiated(self):
        # Arrange
        telnet = Telnet('IBM-3279-2-E')

        telnet.socket = create_autospec(socket, instance=True)

        telnet.is_tn3270e_negotiated = False

        # Act and assert
        with self.assertRaisesRegex(Exception, 'TN3270E mode not negotiated'):
            telnet.send_tn3270e_positive_response(255)

    def test_tn3270e_not_negotiated(self):
        # Arrange
        telnet = Telnet('IBM-3279-2-E')

        telnet.socket = create_autospec(socket, instance=True)

        telnet.is_tn3270e_negotiated = True
        telnet.tn3270e_functions = set()

        # Act and assert
        with self.assertRaisesRegex(Exception, 'TN3270E responses not negotiated'):
            telnet.send_tn3270e_positive_response(255)

class SendTN3270ENegativeResponse(unittest.TestCase):
    def test(self):
        # Arrange
        telnet = Telnet('IBM-3279-2-E')

        telnet.socket = create_autospec(socket, instance=True)

        telnet.is_tn3270e_negotiated = True
        telnet.tn3270e_functions = set([TN3270EFunction.RESPONSES])

        # Act
        telnet.send_tn3270e_negative_response(255, 0x00)

        # Assert
        telnet.socket.sendall.assert_called_with(bytes.fromhex('02 00 01 00 ff ff 00 ff ef'))

    def test_tn3270e_not_negotiated(self):
        # Arrange
        telnet = Telnet('IBM-3279-2-E')

        telnet.socket = create_autospec(socket, instance=True)

        telnet.is_tn3270e_negotiated = False

        # Act and assert
        with self.assertRaisesRegex(Exception, 'TN3270E mode not negotiated'):
            telnet.send_tn3270e_negative_response(255, 0x00)

    def test_tn3270e_not_negotiated(self):
        # Arrange
        telnet = Telnet('IBM-3279-2-E')

        telnet.socket = create_autospec(socket, instance=True)

        telnet.is_tn3270e_negotiated = True
        telnet.tn3270e_functions = set()

        # Act and assert
        with self.assertRaisesRegex(Exception, 'TN3270E responses not negotiated'):
            telnet.send_tn3270e_negative_response(255, 0x00)

class EncodeRFC1646TerminalTypeTestCase(unittest.TestCase):
    def test_no_device_name(self):
        self.assertEqual(encode_rfc1646_terminal_type('IBM-3279-2-E', None), bytes.fromhex('49 42 4d 2d 33 32 37 39 2d 32 2d 45'))

    def test_device_name(self):
        self.assertEqual(encode_rfc1646_terminal_type('IBM-3279-2-E', 'LU1'), bytes.fromhex('49 42 4d 2d 33 32 37 39 2d 32 2d 45 40 4c 55 31'))

class EncodeRFC2355DeviceTypeTestCase(unittest.TestCase):
    def test_no_device_name(self):
        self.assertEqual(encode_rfc2355_device_type('IBM-3278-2-E', None), bytes.fromhex('49 42 4d 2d 33 32 37 38 2d 32 2d 45'))

    def test_device_name(self):
        self.assertEqual(encode_rfc2355_device_type('IBM-3278-2-E', 'LU1'), bytes.fromhex('49 42 4d 2d 33 32 37 38 2d 32 2d 45 01 4c 55 31'))

class DecodeRFC2355DeviceTypeTestCase(unittest.TestCase):
    def test_no_device_name(self):
        self.assertEqual(decode_rfc2355_device_type(bytes.fromhex('49 42 4d 2d 33 32 37 38 2d 32 2d 45')), ('IBM-3278-2-E', None))

    def test_device_name(self):
        self.assertEqual(decode_rfc2355_device_type(bytes.fromhex('49 42 4d 2d 33 32 37 38 2d 32 2d 45 01 4c 55 31')), ('IBM-3278-2-E', 'LU1'))
