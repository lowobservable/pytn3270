import unittest
from unittest.mock import Mock, create_autospec

import string

import context

from tn3270.telnet import Telnet, TN3270EMessageHeader, TN3270EDataType, TN3270EResponseFlag
from tn3270.emulator import Emulator, AttributeCell, CharacterCell, ProtectedCellOperatorError, FieldOverflowOperatorError
from tn3270.datastream import AID

SCREEN1 = bytes.fromhex(('05c3110000e2d6d4c5e3c8c9d5c740c9d540e3c8c540c6c9d9e2e340d9d6e611'
                         '00503c00a07e110154d5d6d9d4c1d3110168c9d5e3c5d5e2c511017cc8c9c4c4'
                         'c5d5110190d7d9d6e3c5c3e3c5c41101a31d60e7e7e7e7e7e7e7e7e7e71101b7'
                         '1de8e7e7e7e7e7e7e7e7e7e71101cb1d6ce7e7e7e7e7e7e7e7e7e71d601101e0'
                         'e4d5d7d9d6e3c5c3e3c5c41101f31d401101fe1df01102071dc81102121df011'
                         '021b1d4c1102261df0110230d5e4d4c5d9c9c31102431d5011024e1df0110257'
                         '1dd81102621df011026b1d5c1102761df0110280d7d9c5c6c9d3d3c5c4110293'
                         '1d40e7e7e7e7e711029e1df01102a71dc8e7e7e7e7e71102b21df01102bb1d4c'
                         'e7e7e7e7e71102c61df01102d0d4d6c4c9c6c9c5c41102e31dc1e7e7e7e7e711'
                         '02ee1df01102f71dc9e7e7e7e7e71103021df011030b1d4de7e7e7e7e7110316'
                         '1df0110370d5d640e2d2c9d71103831d4011038e1d601101f813'))

SCREEN2 = bytes.fromhex('05c11100151d304c606011076760606e1d00')

SCREEN3 = bytes.fromhex(('05c311000060606e1d001101a41d304c60601101b860606e1d001101c21d304c'
                         '60601101f460606e1d001101fe1d304c606011020860606e1d001102121d304c'
                         '606011000413'))

SCREEN4 = bytes.fromhex('05c1110015e38889a240a283998585954089a240a4958696999481a3a38584')

class UpdateTestCase(unittest.TestCase):
    def setUp(self):
        self.stream = create_autospec(Telnet, instance=True)

        self.emulator = Emulator(self.stream, 43, 80)

    def test_no_message(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[])

        # Act and assert
        self.assertFalse(self.emulator.update())

    def test_write(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(bytes.fromhex('01 c3 11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'), None)])

        # Act and assert
        self.assertTrue(self.emulator.update())

        self.assertIsInstance(self.emulator.cells[752], AttributeCell)
        self.assertEqual(self.emulator.get_bytes(753, 763), bytes.fromhex('c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'))

    def test_write_wrap(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(bytes.fromhex('01 c3 11 07 7c c1 c2 c3 c4 c5 c6 c7 c8'), None)])

        # Act and assert
        self.assertTrue(self.emulator.update())

        self.assertEqual(self.emulator.get_bytes(0, 3), bytes.fromhex('c5 c6 c7 c8'))
        self.assertEqual(self.emulator.get_bytes(1916, 1919), bytes.fromhex('c1 c2 c3 c4'))

    def test_write_alarm(self):
        # Arrange
        self.emulator.alarm = Mock()

        self.stream.read_multiple = Mock(return_value=[(bytes.fromhex('01 c7'), None)])

        # Act
        self.emulator.update()

        # Assert
        self.emulator.alarm.assert_called()

    def test_read_buffer(self):
        # Arrange
        self.stream.read_multiple = Mock(side_effect=[[(SCREEN1, None)], [(bytes.fromhex('02'), None)]])

        self.emulator.update()

        self.emulator.cursor_address = 505

        for character in 'ABCDEFGHIJ'.encode('ibm037'):
            self.emulator.input(character)

        self.assertEqual(self.emulator.cursor_address, 525)

        self.emulator.aid(AID.ENTER)

        self.stream.write.reset_mock()

        # Act
        self.emulator.update()

        # Assert
        self.stream.write.assert_called()

        bytes_ = self.stream.write.mock_calls[0][1][0]

        self.assertEqual(bytes_[:3], bytes.fromhex('7dc84d'))
        self.assertEqual(bytes_[3:944], bytes.fromhex('e2d6d4c5e3c8c9d5c740c9d540e3c8c540c6c9d9e2e340d9d6e60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d5d6d9d4c1d30000000000000000000000000000c9d5e3c5d5e2c500000000000000000000000000c8c9c4c4c5d50000000000000000000000000000d7d9d6e3c5c3e3c5c4000000000000000000001d60e7e7e7e7e7e7e7e7e7e70000000000000000001de8e7e7e7e7e7e7e7e7e7e70000000000000000001d6ce7e7e7e7e7e7e7e7e7e71d60000000000000000000e4d5d7d9d6e3c5c3e3c5c400000000000000001d410000000000c1c2c3c4c51df000000000000000001dc9c6c7c8c9d100000000001df000000000000000001d4c000000000000000000001df0000000000000000000d5e4d4c5d9c9c30000000000000000000000001d50000000000000000000001df000000000000000001dd8000000000000000000001df000000000000000001d5c000000000000000000001df0000000000000000000d7d9c5c6c9d3d3c5c4000000000000000000001d40e7e7e7e7e700000000001df000000000000000001dc8e7e7e7e7e700000000001df000000000000000001d4ce7e7e7e7e700000000001df0000000000000000000d4d6c4c9c6c9c5c400000000000000000000001dc1e7e7e7e7e700000000001df000000000000000001dc9e7e7e7e7e700000000001df000000000000000001d4de7e7e7e7e700000000001df00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d5d640e2d2c9d70000000000000000000000001d40000000000000000000001d60'))
        self.assertTrue(all([byte == 0x00 for byte in bytes_[944:]]))

    def test_nop(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(bytes.fromhex('03'), None)])

        # Act
        self.emulator.update()

    def test_erase_write_screen1(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        # Act
        self.emulator.update()

        # Assert
        self.assertFalse(self.emulator.alternate)

        self.assertEqual(self.emulator.cursor_address, 504)

        fields = self.emulator.get_fields(protected=False)

        self.assertEqual(len(fields), 13)

        self.assertEqual(fields[0][0], 500)
        self.assertEqual(fields[0][1], 509)
        self.assertFalse(fields[0][2].protected)
        self.assertFalse(fields[0][2].numeric)
        self.assertFalse(fields[0][2].intensified)
        self.assertFalse(fields[0][2].hidden)
        self.assertFalse(fields[0][2].modified)

        self.assertEqual(fields[1][0], 520)
        self.assertEqual(fields[1][1], 529)
        self.assertFalse(fields[1][2].protected)
        self.assertFalse(fields[1][2].numeric)
        self.assertTrue(fields[1][2].intensified)
        self.assertFalse(fields[1][2].hidden)
        self.assertFalse(fields[1][2].modified)

        self.assertEqual(fields[2][0], 540)
        self.assertEqual(fields[2][1], 549)
        self.assertFalse(fields[2][2].protected)
        self.assertFalse(fields[2][2].numeric)
        self.assertFalse(fields[2][2].intensified)
        self.assertTrue(fields[2][2].hidden)
        self.assertFalse(fields[2][2].modified)

        self.assertEqual(fields[3][0], 580)
        self.assertEqual(fields[3][1], 589)
        self.assertFalse(fields[3][2].protected)
        self.assertTrue(fields[3][2].numeric)
        self.assertFalse(fields[3][2].intensified)
        self.assertFalse(fields[3][2].hidden)
        self.assertFalse(fields[3][2].modified)

        self.assertEqual(fields[4][0], 600)
        self.assertEqual(fields[4][1], 609)
        self.assertFalse(fields[4][2].protected)
        self.assertTrue(fields[4][2].numeric)
        self.assertTrue(fields[4][2].intensified)
        self.assertFalse(fields[4][2].hidden)
        self.assertFalse(fields[4][2].modified)

        self.assertEqual(fields[5][0], 620)
        self.assertEqual(fields[5][1], 629)
        self.assertFalse(fields[5][2].protected)
        self.assertTrue(fields[5][2].numeric)
        self.assertFalse(fields[5][2].intensified)
        self.assertTrue(fields[5][2].hidden)
        self.assertFalse(fields[5][2].modified)

        self.assertEqual(fields[6][0], 660)
        self.assertEqual(fields[6][1], 669)

        self.assertEqual(fields[7][0], 680)
        self.assertEqual(fields[7][1], 689)

        self.assertEqual(fields[8][0], 700)
        self.assertEqual(fields[8][1], 709)

        self.assertEqual(fields[9][0], 740)
        self.assertEqual(fields[9][1], 749)
        self.assertFalse(fields[9][2].protected)
        self.assertFalse(fields[9][2].numeric)
        self.assertFalse(fields[9][2].intensified)
        self.assertFalse(fields[9][2].hidden)
        self.assertTrue(fields[9][2].modified)

        self.assertEqual(fields[10][0], 760)
        self.assertEqual(fields[10][1], 769)
        self.assertFalse(fields[10][2].protected)
        self.assertFalse(fields[10][2].numeric)
        self.assertTrue(fields[10][2].intensified)
        self.assertFalse(fields[10][2].hidden)
        self.assertTrue(fields[11][2].modified)

        self.assertEqual(fields[11][0], 780)
        self.assertEqual(fields[11][1], 789)
        self.assertFalse(fields[11][2].protected)
        self.assertFalse(fields[11][2].numeric)
        self.assertFalse(fields[11][2].intensified)
        self.assertTrue(fields[11][2].hidden)
        self.assertTrue(fields[11][2].modified)

        self.assertEqual(fields[12][0], 900)
        self.assertEqual(fields[12][1], 909)

    def test_erase_write_screen2(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(SCREEN2, None)])

        # Act
        self.emulator.update()

        # Assert
        self.assertFalse(self.emulator.alternate)

        fields = self.emulator.get_fields(protected=False)

        self.assertEqual(len(fields), 1)

        self.assertEqual(fields[0][0], 1899)
        self.assertEqual(fields[0][1], 20)
        self.assertFalse(fields[0][2].protected)
        self.assertFalse(fields[0][2].numeric)
        self.assertFalse(fields[0][2].intensified)
        self.assertFalse(fields[0][2].hidden)
        self.assertFalse(fields[0][2].modified)

    def test_read_modified(self):
        # Arrange
        self.stream.read_multiple = Mock(side_effect=[[(SCREEN1, None)], [(bytes.fromhex('06'), None)]])

        self.emulator.update()

        self.emulator.cursor_address = 505

        for character in 'ABCDEFGHIJ'.encode('ibm037'):
            self.emulator.input(character)

        self.assertEqual(self.emulator.cursor_address, 525)

        self.emulator.aid(AID.ENTER)

        self.stream.write.reset_mock()

        # Act
        self.emulator.update()

        # Assert
        self.stream.write.assert_called_with(bytes.fromhex('7dc84d11c7f4c1c2c3c4c511c8c8c6c7c8c9d1114be4e7e7e7e7e7114bf8e7e7e7e7e7114c4ce7e7e7e7e7'))

    def test_erase_write_alternate_screen1(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(bytes([0x0d, *SCREEN1[1:]]), None)])

        # Act
        self.emulator.update()

        # Assert
        self.assertTrue(self.emulator.alternate)

        fields = self.emulator.get_fields(protected=False)

        self.assertEqual(len(fields), 13)

    def test_read_modified_all(self):
        # Arrange
        self.stream.read_multiple = Mock(side_effect=[[(SCREEN1, None)], [(bytes.fromhex('0e'), None)]])

        self.emulator.update()

        self.emulator.cursor_address = 505

        for character in 'ABCDEFGHIJ'.encode('ibm037'):
            self.emulator.input(character)

        self.assertEqual(self.emulator.cursor_address, 525)

        self.emulator.aid(AID.PA1)

        self.stream.write.reset_mock()

        # Act
        self.emulator.update()

        # Assert
        self.stream.write.assert_called_with(bytes.fromhex('6cc84d11c7f4c1c2c3c4c511c8c8c6c7c8c9d1114be4e7e7e7e7e7114bf8e7e7e7e7e7114c4ce7e7e7e7e7'))

    def test_erase_all_unprotected(self):
        # Arrange
        self.stream.read_multiple = Mock(side_effect=[[(SCREEN1, None)], [(bytes.fromhex('0f'), None)]])

        self.emulator.update()

        self.emulator.cursor_address = 505

        for character in 'ABCDEFGHIJ'.encode('ibm037'):
            self.emulator.input(character)

        self.emulator.current_aid = AID.ENTER
        self.emulator.keyboard_locked = True

        self.assertEqual(self.emulator.cursor_address, 525)

        fields = self.emulator.get_fields(protected=False)

        self.assertTrue(fields[0][2].modified)
        self.assertEqual(self.emulator.get_bytes(fields[0][0], fields[0][1]), bytes.fromhex('0000000000c1c2c3c4c5'))

        self.assertTrue(fields[1][2].modified)
        self.assertEqual(self.emulator.get_bytes(fields[1][0], fields[1][1]), bytes.fromhex('c6c7c8c9d10000000000'))

        # Act
        self.emulator.update()

        # Assert
        fields = self.emulator.get_fields(protected=False)

        self.assertFalse(fields[0][2].modified)
        self.assertEqual(self.emulator.get_bytes(fields[0][0], fields[0][1]), bytes.fromhex('00000000000000000000'))

        self.assertFalse(fields[1][2].modified)
        self.assertEqual(self.emulator.get_bytes(fields[1][0], fields[1][1]), bytes.fromhex('00000000000000000000'))

        self.assertEqual(self.emulator.current_aid, AID.NONE)
        self.assertFalse(self.emulator.keyboard_locked)

    def test_write_structured_field_read_partition_query(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(bytes.fromhex('11 00 05 01 ff 02'), None)])

        # Act
        self.emulator.update()

        # Assert
        self.stream.write.assert_called_with(bytes.fromhex('88 00 0b 81 80 80 81 84 86 87 88 a6 00 17 81 81 01 00 00 50 00 2b 01 00 0a 02 e5 00 02 00 6f 09 0c 0d 70 00 08 81 84 01 0d 70 00 00 16 81 86 00 08 00 f4 f1 f1 f2 f2 f3 f3 f4 f4 f5 f5 f6 f6 f7 f7 00 0d 81 87 04 00 f0 f1 f1 f2 f2 f4 f4 00 06 81 88 00 01 00 11 81 a6 00 00 0b 01 00 00 50 00 18 00 50 00 2b'))

    def test_tn3270e_successful_with_no_response_flag(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(bytes.fromhex('01 c3 11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'), TN3270EMessageHeader(TN3270EDataType.DATA_3270, None, TN3270EResponseFlag.NO, 123))])

        # Act
        self.emulator.update()

        # Assert
        self.stream.send_tn3270e_positive_response.assert_not_called()

    def test_tn3270e_error_with_no_response_flag(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(bytes.fromhex('01 c3 11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'), TN3270EMessageHeader(TN3270EDataType.DATA_3270, None, TN3270EResponseFlag.NO, 123))])

        self.emulator._execute = Mock(side_effect=Exception('Error'))

        # Act
        with self.assertRaises(Exception):
            self.emulator.update()

        # Assert
        self.stream.send_tn3270e_negative_response.assert_not_called()

    def test_tn3270e_successful_with_error_response_flag(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(bytes.fromhex('01 c3 11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'), TN3270EMessageHeader(TN3270EDataType.DATA_3270, None, TN3270EResponseFlag.ERROR, 123))])

        # Act
        self.emulator.update()

        # Assert
        self.stream.send_tn3270e_positive_response.assert_not_called()

    def test_tn3270e_error_with_error_response_flag(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(bytes.fromhex('01 c3 11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'), TN3270EMessageHeader(TN3270EDataType.DATA_3270, None, TN3270EResponseFlag.ERROR, 123))])

        self.emulator._execute = Mock(side_effect=Exception('Error'))

        # Act
        with self.assertRaises(Exception):
            self.emulator.update()

        # Assert
        self.stream.send_tn3270e_negative_response.assert_called_once_with(123, 0)

    def test_tn3270e_successful_with_always_response_flag(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(bytes.fromhex('01 c3 11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'), TN3270EMessageHeader(TN3270EDataType.DATA_3270, None, TN3270EResponseFlag.ALWAYS, 123))])

        # Act
        self.emulator.update()

        # Assert
        self.stream.send_tn3270e_positive_response.assert_called_once_with(123)

    def test_tn3270e_error_with_always_response_flag(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(bytes.fromhex('01 c3 11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'), TN3270EMessageHeader(TN3270EDataType.DATA_3270, None, TN3270EResponseFlag.ALWAYS, 123))])

        self.emulator._execute = Mock(side_effect=Exception('Error'))

        # Act
        with self.assertRaises(Exception):
            self.emulator.update()

        # Assert
        self.stream.send_tn3270e_negative_response.assert_called_once_with(123, 0)

class AidTestCase(unittest.TestCase):
    def setUp(self):
        self.stream = create_autospec(Telnet, instance=True)

        self.stream.write = Mock()

        self.emulator = Emulator(self.stream, 24, 80)

    def test_screen1_short_read(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        self.emulator.update()

        self.emulator.cursor_address = 500

        for character in 'ABCDEFGHIJKLMNO'.encode('ibm037'):
            self.emulator.input(character)

        self.assertEqual(self.emulator.cursor_address, 525)

        # Act
        self.emulator.aid(AID.PA1)

        # Assert
        self.stream.write.assert_called_with(bytes.fromhex('6c'))

    def test_screen1_long_read(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        self.emulator.update()

        self.emulator.cursor_address = 505

        for character in 'ABCDEFGHIJ'.encode('ibm037'):
            self.emulator.input(character)

        self.assertEqual(self.emulator.cursor_address, 525)

        # Act
        self.emulator.aid(AID.ENTER)

        # Assert
        self.stream.write.assert_called_with(bytes.fromhex('7dc84d11c7f4c1c2c3c4c511c8c8c6c7c8c9d1114be4e7e7e7e7e7114bf8e7e7e7e7e7114c4ce7e7e7e7e7'))

    def test_screen2_long_read(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(SCREEN2, None)])

        self.emulator.update()

        self.emulator.cursor_address = 0

        for character in (string.ascii_uppercase + string.ascii_lowercase).encode('ibm037'):
            self.emulator.input(character)

        self.assertEqual(self.emulator.cursor_address, 10)

        # Act
        self.emulator.aid(AID.ENTER)

        # Assert
        self.stream.write.assert_called_with(bytes.fromhex('7d404a115d6be5e6e7e8e9818283848586878889919293949596979899a2a3a4a5a6a7a8a9d2d3d4d5d6d7d8d9e2e3e4'))

    def test_clear(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        self.emulator.update()

        self.emulator.cursor_address = 505

        for character in 'ABCDEFGHIJ'.encode('ibm037'):
            self.emulator.input(character)

        self.assertEqual(self.emulator.cursor_address, 525)

        # Act
        self.emulator.aid(AID.CLEAR)

        # Assert
        self.stream.write.assert_called_with(bytes.fromhex('6d'))

        self.assertEqual(self.emulator.address, 0)

        self.assertTrue(all([isinstance(cell, CharacterCell) and cell.byte == 0x00 for cell in self.emulator.cells]))

        self.assertEqual(self.emulator.cursor_address, 0)

class TabTestCase(unittest.TestCase):
    def setUp(self):
        self.stream = create_autospec(Telnet, instance=True)

        self.stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        self.emulator = Emulator(self.stream, 24, 80)

        self.emulator.update()

        self.emulator.cursor_address = 0

    def test_blank_screen(self):
        # Arrange
        self.emulator = Emulator(None, 24, 80)

        self.assertEqual(self.emulator.cursor_address, 0)

        # Act
        self.emulator.tab()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 0)

    def test_forward(self):
        for address in [0, 498, 499]:
            with self.subTest(address=address):
                # Arrange
                self.emulator.cursor_address = address

                # Act
                self.emulator.tab()

                # Assert
                self.assertEqual(self.emulator.cursor_address, 500)

    def test_forward_to_next_field(self):
        # Arrange
        self.emulator.cursor_address = 500

        # Act
        self.emulator.tab()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 520)

    def test_backward(self):
        for address in [520, 519, 510]:
            with self.subTest(address=address):
                # Arrange
                self.emulator.cursor_address = address

                # Act
                self.emulator.tab(direction=-1)

                # Assert
                self.assertEqual(self.emulator.cursor_address, 500)

    def test_backward_to_start_of_field(self):
        # Arrange
        self.emulator.cursor_address = 505

        # Act
        self.emulator.tab(direction=-1)

        # Assert
        self.assertEqual(self.emulator.cursor_address, 500)

    def test_wrap_forward(self):
        # Arrange
        self.emulator.cursor_address = 900

        # Act
        self.emulator.tab()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 500)

    def test_wrap_backward(self):
        # Arrange
        self.emulator.cursor_address = 500

        # Act
        self.emulator.tab(direction=-1)

        # Assert
        self.assertEqual(self.emulator.cursor_address, 900)

class NewlineTestCase(unittest.TestCase):
    def setUp(self):
        self.stream = create_autospec(Telnet, instance=True)

        self.stream.read_multiple = Mock(return_value=[(SCREEN3, None)])

        self.emulator = Emulator(self.stream, 24, 80)

        self.emulator.update()

        self.emulator.cursor_address = 0

    def test_blank_screen(self):
        # Arrange
        self.emulator = Emulator(None, 24, 80)

        self.assertEqual(self.emulator.cursor_address, 0)

        # Act
        self.emulator.newline()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 0)

    def test_next_line(self):
        for address in [0, 1, 20]:
            with self.subTest(address=address):
                # Arrange
                self.emulator.cursor_address = address

                # Act
                self.emulator.newline()

                # Assert
                self.assertEqual(self.emulator.cursor_address, 80)

    def test_first_field_on_next_line(self):
        # Arrange
        self.emulator.cursor_address = 400

        # Act
        self.emulator.newline()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 504)

    def test_wrap(self):
        # Arrange
        self.emulator.cursor_address = 504

        # Act
        self.emulator.newline()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 4)

class HomeTestCase(unittest.TestCase):
    def setUp(self):
        self.stream = create_autospec(Telnet, instance=True)

        self.stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        self.emulator = Emulator(self.stream, 24, 80)

        self.emulator.update()

        self.emulator.cursor_address = 0

    def test_blank_screen(self):
        # Arrange
        self.emulator = Emulator(None, 24, 80)

        self.assertEqual(self.emulator.cursor_address, 0)

        # Act
        self.emulator.home()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 0)

    def test(self):
        for address in [0, 498, 499, 500, 505, 510]:
            with self.subTest(address=address):
                # Arrange
                self.emulator.cursor_address = address

                # Act
                self.emulator.home()

                # Assert
                self.assertEqual(self.emulator.cursor_address, 500)

class CursorUpTestCase(unittest.TestCase):
    def setUp(self):
        self.emulator = Emulator(None, 24, 80)

    def test_first_row(self):
        # Arrange
        self.emulator.cursor_address = 20

        # Act
        self.emulator.cursor_up()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 1860)

    def test_last_row(self):
        # Arrange
        self.emulator.cursor_address = 1860

        # Act
        self.emulator.cursor_up()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 1780)

class CursorDownTestCase(unittest.TestCase):
    def setUp(self):
        self.emulator = Emulator(None, 24, 80)

    def test_first_row(self):
        # Arrange
        self.emulator.cursor_address = 20

        # Act
        self.emulator.cursor_down()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 100)

    def test_last_row(self):
        # Arrange
        self.emulator.cursor_address = 1860

        # Act
        self.emulator.cursor_down()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 20)

class CursorLeftTestCase(unittest.TestCase):
    def setUp(self):
        self.emulator = Emulator(None, 24, 80)

    def test_first_cell(self):
        # Arrange
        self.emulator.cursor_address = 0

        # Act
        self.emulator.cursor_left()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 1919)

    def test_last_cell(self):
        # Arrange
        self.emulator.cursor_address = 1919

        # Act
        self.emulator.cursor_left()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 1918)

    def test_fast(self):
        # Arrange
        self.emulator.cursor_address = 1919

        # Act
        self.emulator.cursor_left(2)

        # Assert
        self.assertEqual(self.emulator.cursor_address, 1917)

    def test_invalid_rate(self):
        for rate in [-1, 0, 3]:
            with self.subTest(rate=rate):
                with self.assertRaisesRegex(ValueError, 'Invalid rate'):
                    self.emulator.cursor_left(rate)

class CursorRightTestCase(unittest.TestCase):
    def setUp(self):
        self.emulator = Emulator(None, 24, 80)

    def test_first_cell(self):
        # Arrange
        self.emulator.cursor_address = 0

        # Act
        self.emulator.cursor_right()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 1)

    def test_last_cell(self):
        # Arrange
        self.emulator.cursor_address = 1919

        # Act
        self.emulator.cursor_right()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 0)

    def test_fast(self):
        # Arrange
        self.emulator.cursor_address = 0

        # Act
        self.emulator.cursor_right(2)

        # Assert
        self.assertEqual(self.emulator.cursor_address, 2)

    def test_invalid_rate(self):
        for rate in [-1, 0, 3]:
            with self.subTest(rate=rate):
                with self.assertRaisesRegex(ValueError, 'Invalid rate'):
                    self.emulator.cursor_right(rate)

class InputTestCase(unittest.TestCase):
    def setUp(self):
        self.stream = create_autospec(Telnet, instance=True)

        self.emulator = Emulator(self.stream, 24, 80)

        self.stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        self.emulator.update()

    def test_attribute_cell(self):
        # Arrange
        self.emulator.cursor_address = 499

        # Act and assert
        with self.assertRaises(ProtectedCellOperatorError):
            self.emulator.input(0xe7)

    def test_protected_cell(self):
        # Arrange
        self.emulator.cursor_address = 420

        # Act and assert
        with self.assertRaises(ProtectedCellOperatorError):
            self.emulator.input(0xe7)

    def test_alphanumeric(self):
        # Arrange
        self.emulator.cursor_address = 500

        self.assertFalse(self.emulator.cells[499].attribute.modified)

        # Act
        self.emulator.input(0xe7)

        # Assert
        self.assertEqual(self.emulator.cursor_address, 501)
        self.assertTrue(self.emulator.cells[499].attribute.modified)
        self.assertEqual(self.emulator.cells[500].byte, 0xe7)

    def test_skip(self):
        # Arrange
        self.emulator.cursor_address = 500

        self.assertTrue(self.emulator.cells[510].attribute.skip)

        # Act
        for _ in range(10):
            self.emulator.input(0xe7)

        # Assert
        self.assertEqual(self.emulator.cursor_address, 520)

    def test_no_skip(self):
        # Arrange
        self.emulator.cursor_address = 900

        self.assertFalse(self.emulator.cells[910].attribute.skip)

        # Act
        for _ in range(10):
            self.emulator.input(0xe7)

        # Assert
        self.assertEqual(self.emulator.cursor_address, 911)

    def test_wrap(self):
        # Arrange
        self.stream = create_autospec(Telnet, instance=True)

        self.emulator = Emulator(self.stream, 24, 80)

        self.stream.read_multiple = Mock(return_value=[(SCREEN2, None)])

        self.emulator.update()

        fields = self.emulator.get_fields(protected=False)

        self.assertEqual(len(fields), 1)

        self.assertEqual(fields[0][0], 1899)
        self.assertEqual(fields[0][1], 20)

        self.assertEqual(self.emulator.cursor_address, 0)

        # Act
        for character in (string.ascii_uppercase + string.ascii_lowercase).encode('ibm037'):
            self.emulator.input(character)

        # Assert
        self.assertEqual(self.emulator.cursor_address, 10)

        text = self.emulator.get_bytes(fields[0][0], fields[0][1]).decode('ibm037')

        self.assertEqual(text, 'VWXYZabcdefghijklmnopqrstuvwxyzKLMNOPQRSTU')

    def test_insert(self):
        # Arrange
        self.emulator.cursor_address = 500

        self.emulator.input(0xc1)
        self.emulator.input(0xc4)
        self.emulator.input(0xc5)

        self.emulator.cursor_address = 504

        self.emulator.input(0xc6)
        self.emulator.input(0xc7)
        self.emulator.input(0x40)
        self.emulator.input(0xc8)

        self.assertEqual(self.emulator.get_bytes(500, 509), bytes.fromhex('c1 c4 c5 00 c6 c7 40 c8 00 00'))

        self.emulator.cursor_address = 501

        # Act
        self.emulator.input(0xc2, insert=True)
        self.emulator.input(0xc3, insert=True)

        # Assert
        self.assertEqual(self.emulator.cursor_address, 503)

        self.assertEqual(self.emulator.get_bytes(500, 509), bytes.fromhex('c1 c2 c3 c4 c5 c6 c7 40 c8 00'))

    def test_insert_overflow(self):
        # Arrange
        self.emulator.cursor_address = 505

        self.emulator.input(0xc1)
        self.emulator.input(0xc2)
        self.emulator.input(0xc3)
        self.emulator.input(0xc4)
        self.emulator.input(0xc5)

        self.emulator.cursor_address = 505

        # Act and assert
        with self.assertRaises(FieldOverflowOperatorError):
            self.emulator.input(0xc1, insert=True)

class DupTestCase(unittest.TestCase):
    def setUp(self):
        self.stream = create_autospec(Telnet, instance=True)

        self.emulator = Emulator(self.stream, 24, 80)

        self.stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        self.emulator.update()

    def test_attribute_cell(self):
        # Arrange
        self.emulator.cursor_address = 499

        # Act and assert
        with self.assertRaises(ProtectedCellOperatorError):
            self.emulator.dup()

    def test_protected_cell(self):
        # Arrange
        self.emulator.cursor_address = 420

        # Act and assert
        with self.assertRaises(ProtectedCellOperatorError):
            self.emulator.dup()

    def test_first_field_character(self):
        # Arrange
        self.emulator.cursor_address = 500

        # Act
        self.emulator.dup()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 520)
        self.assertTrue(self.emulator.cells[499].attribute.modified)
        self.assertEqual(self.emulator.cells[500].byte, 0x1c)

class BackspaceTestCase(unittest.TestCase):
    def setUp(self):
        self.stream = create_autospec(Telnet, instance=True)

        self.emulator = Emulator(self.stream, 24, 80)

        self.stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        self.emulator.update()

    def test_attribute_cell(self):
        # Arrange
        self.emulator.cursor_address = 499

        # Act and assert
        with self.assertRaises(ProtectedCellOperatorError):
            self.emulator.backspace()

    def test_protected_cell(self):
        # Arrange
        self.emulator.cursor_address = 420

        # Act and assert
        with self.assertRaises(ProtectedCellOperatorError):
            self.emulator.backspace()

    def test_first_field_character(self):
        # Arrange
        self.emulator.cursor_address = 660

        self.assertFalse(self.emulator.cells[659].attribute.modified)

        # Act
        self.emulator.backspace()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 660)
        self.assertFalse(self.emulator.cells[659].attribute.modified)
        self.assertEqual(self.emulator.cells[660].byte, 0xe7)

    def test_from_middle_to_start(self):
        # Arrange
        address = 660

        for character in 'ABCDEFGHIJ'.encode('ibm037'):
            self.emulator.cells[address].byte = character

            address += 1

        self.emulator.cursor_address = 665

        self.assertFalse(self.emulator.cells[659].attribute.modified)

        # Act
        for _ in range(5):
            self.emulator.backspace()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 660)
        self.assertTrue(self.emulator.cells[659].attribute.modified)
        self.assertEqual(self.emulator.get_bytes(660, 669), bytes.fromhex('c6c7c8c9d10000000000'))

    def test_from_end_to_start(self):
        # Arrange
        address = 660

        for character in 'ABCDEFGHIJ'.encode('ibm037'):
            self.emulator.cells[address].byte = character

            address += 1

        self.emulator.cursor_address = 669

        self.assertFalse(self.emulator.cells[659].attribute.modified)

        # Act
        for _ in range(10):
            self.emulator.backspace()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 660)
        self.assertTrue(self.emulator.cells[659].attribute.modified)
        self.assertEqual(self.emulator.get_bytes(660, 669), bytes.fromhex('d1000000000000000000'))

class DeleteTestCase(unittest.TestCase):
    def setUp(self):
        self.stream = create_autospec(Telnet, instance=True)

        self.emulator = Emulator(self.stream, 24, 80)

        self.stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        self.emulator.update()

    def test_attribute_cell(self):
        # Arrange
        self.emulator.cursor_address = 499

        # Act and assert
        with self.assertRaises(ProtectedCellOperatorError):
            self.emulator.delete()

    def test_protected_cell(self):
        # Arrange
        self.emulator.cursor_address = 420

        # Act and assert
        with self.assertRaises(ProtectedCellOperatorError):
            self.emulator.delete()

    def test_from_middle_to_end(self):
        # Arrange
        address = 660

        for character in 'ABCDEFGHIJ'.encode('ibm037'):
            self.emulator.cells[address].byte = character

            address += 1

        self.emulator.cursor_address = 665

        self.assertFalse(self.emulator.cells[659].attribute.modified)

        # Act
        for _ in range(5):
            self.emulator.delete()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 665)
        self.assertTrue(self.emulator.cells[659].attribute.modified)
        self.assertEqual(self.emulator.get_bytes(660, 669), bytes.fromhex('c1c2c3c4c50000000000'))

    def test_from_start_to_end(self):
        # Arrange
        address = 660

        for character in 'ABCDEFGHIJ'.encode('ibm037'):
            self.emulator.cells[address].byte = character

            address += 1

        self.emulator.cursor_address = 660

        self.assertFalse(self.emulator.cells[659].attribute.modified)

        # Act
        for _ in range(10):
            self.emulator.delete()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 660)
        self.assertTrue(self.emulator.cells[659].attribute.modified)
        self.assertEqual(self.emulator.get_bytes(660, 669), bytes.fromhex('00000000000000000000'))

class EraseEndOfFieldTestCase(unittest.TestCase):
    def setUp(self):
        self.stream = create_autospec(Telnet, instance=True)

        self.emulator = Emulator(self.stream, 24, 80)

        self.stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        self.emulator.update()

    def test_attribute_cell(self):
        # Arrange
        self.emulator.cursor_address = 499

        # Act and assert
        with self.assertRaises(ProtectedCellOperatorError):
            self.emulator.erase_end_of_field()

    def test_protected_cell(self):
        # Arrange
        self.emulator.cursor_address = 420

        # Act and assert
        with self.assertRaises(ProtectedCellOperatorError):
            self.emulator.erase_end_of_field()

    def test_from_middle(self):
        # Arrange
        address = 660

        for character in 'ABCDEFGHIJ'.encode('ibm037'):
            self.emulator.cells[address].byte = character

            address += 1

        self.emulator.cursor_address = 665

        self.assertFalse(self.emulator.cells[659].attribute.modified)

        # Act
        self.emulator.erase_end_of_field()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 665)
        self.assertTrue(self.emulator.cells[659].attribute.modified)
        self.assertEqual(self.emulator.get_bytes(660, 669), bytes.fromhex('c1c2c3c4c50000000000'))

    def test_from_start(self):
        # Arrange
        address = 660

        for character in 'ABCDEFGHIJ'.encode('ibm037'):
            self.emulator.cells[address].byte = character

            address += 1

        self.emulator.cursor_address = 660

        self.assertFalse(self.emulator.cells[659].attribute.modified)

        # Act
        self.emulator.erase_end_of_field()

        # Assert
        self.assertEqual(self.emulator.cursor_address, 660)
        self.assertTrue(self.emulator.cells[659].attribute.modified)
        self.assertEqual(self.emulator.get_bytes(660, 669), bytes.fromhex('00000000000000000000'))

class EraseInputTestCase(unittest.TestCase):
    def test(self):
        # Arrange
        stream = create_autospec(Telnet, instance=True)

        emulator = Emulator(stream, 24, 80)

        stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        emulator.update()

        emulator.cursor_address = 505

        for character in 'ABCDEFGHIJ'.encode('ibm037'):
            emulator.input(character)

        fields = emulator.get_fields(protected=False)

        self.assertTrue(fields[0][2].modified)
        self.assertEqual(emulator.get_bytes(fields[0][0], fields[0][1]), bytes.fromhex('0000000000c1c2c3c4c5'))

        self.assertTrue(fields[1][2].modified)
        self.assertEqual(emulator.get_bytes(fields[1][0], fields[1][1]), bytes.fromhex('c6c7c8c9d10000000000'))

        # Act
        emulator.erase_input()

        # Assert
        fields = emulator.get_fields(protected=False)

        self.assertFalse(fields[0][2].modified)
        self.assertEqual(emulator.get_bytes(fields[0][0], fields[0][1]), bytes.fromhex('00000000000000000000'))

        self.assertFalse(fields[1][2].modified)
        self.assertEqual(emulator.get_bytes(fields[1][0], fields[1][1]), bytes.fromhex('00000000000000000000'))

class IsFormattedTestCase(unittest.TestCase):
    def setUp(self):
        self.stream = create_autospec(Telnet, instance=True)

        self.emulator = Emulator(self.stream, 24, 80)

    def test_formatted(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        self.emulator.update()

        # Act and assert
        self.assertTrue(self.emulator.is_formatted())

    def test_unformatted(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[(SCREEN4, None)])

        self.emulator.update()

        # Act and assert
        self.assertFalse(self.emulator.is_formatted())

class GetFieldsTestCase(unittest.TestCase):
    def setUp(self):
        self.stream = create_autospec(Telnet, instance=True)

        self.emulator = Emulator(self.stream, 24, 80)

        self.stream.read_multiple = Mock(return_value=[(SCREEN1, None)])

        self.emulator.update()

    def test_all(self):
        # Act
        fields = self.emulator.get_fields()

        # Assert
        self.assertEqual(len(fields), 30)

    def test_protected(self):
        # Act
        fields = self.emulator.get_fields(protected=True)

        # Assert
        self.assertEqual(len(fields), 17)

    def test_unprotected(self):
        # Act
        fields = self.emulator.get_fields(protected=False)

        # Assert
        self.assertEqual(len(fields), 13)

    def test_modified(self):
        # Act
        fields = self.emulator.get_fields(modified=True)

        # Assert
        self.assertEqual(len(fields), 3)

    def test_unmodified(self):
        # Act
        fields = self.emulator.get_fields(modified=False)

        # Assert
        self.assertEqual(len(fields), 27)
