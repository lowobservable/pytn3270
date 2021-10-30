import unittest

import context

from tn3270.attributes import Attribute, ExtendedAttribute, HighlightExtendedAttribute, ForegroundColorExtendedAttribute
from tn3270.datastream import Command, Order, AID, WCC, parse_outbound_message, format_inbound_read_modified_message, parse_orders, parse_outbound_structured_fields, format_inbound_structured_fields, parse_extended_attribute, parse_address, format_address

class WCCTestCase(unittest.TestCase):
    def test_reset(self):
        # Act
        wcc = WCC(0b01000000)

        # Assert
        self.assertTrue(wcc.reset)
        self.assertFalse(wcc.alarm)
        self.assertFalse(wcc.unlock_keyboard)
        self.assertFalse(wcc.reset_modified)

    def test_alarm(self):
        # Act
        wcc = WCC(0b00000100)

        # Assert
        self.assertFalse(wcc.reset)
        self.assertTrue(wcc.alarm)
        self.assertFalse(wcc.unlock_keyboard)
        self.assertFalse(wcc.reset_modified)

    def test_unlock_keyboard(self):
        # Act
        wcc = WCC(0b00000010)

        # Assert
        self.assertFalse(wcc.reset)
        self.assertFalse(wcc.alarm)
        self.assertTrue(wcc.unlock_keyboard)
        self.assertFalse(wcc.reset_modified)

    def test_reset_modified(self):
        # Act
        wcc = WCC(0b00000001)

        # Assert
        self.assertFalse(wcc.reset)
        self.assertFalse(wcc.alarm)
        self.assertFalse(wcc.unlock_keyboard)
        self.assertTrue(wcc.reset_modified)

class ParseOutboundMessageTestCase(unittest.TestCase):
    def test_write(self):
        # Act
        (command, wcc, orders) = parse_outbound_message(bytes.fromhex('01 c3 11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'))

        # Assert
        self.assertEqual(command, Command.W)

        self.assertIsInstance(wcc, WCC)
        self.assertEqual(wcc.value, 0xc3)

        self.assertEqual([order[0] for order in orders], [Order.SBA, Order.SF, None])

    def test_sna_write(self):
        # Act
        (command, wcc, orders) = parse_outbound_message(bytes.fromhex('f1 c3 11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'))

        # Assert
        self.assertEqual(command, Command.W)

        self.assertIsInstance(wcc, WCC)
        self.assertEqual(wcc.value, 0xc3)

        self.assertEqual([order[0] for order in orders], [Order.SBA, Order.SF, None])

    def test_read_buffer(self):
        self.assertEqual(parse_outbound_message(bytes.fromhex('02')), (Command.RB,))

    def test_sna_read_buffer(self):
        self.assertEqual(parse_outbound_message(bytes.fromhex('f2')), (Command.RB,))

    def test_nop(self):
        self.assertEqual(parse_outbound_message(bytes.fromhex('03')), (Command.NOP,))

    def test_erase_write(self):
        # Act
        (command, wcc, orders) = parse_outbound_message(bytes.fromhex('05 c3 11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'))

        # Assert
        self.assertEqual(command, Command.EW)

        self.assertIsInstance(wcc, WCC)
        self.assertEqual(wcc.value, 0xc3)

        self.assertEqual([order[0] for order in orders], [Order.SBA, Order.SF, None])

    def test_sna_erase_write(self):
        # Act
        (command, wcc, orders) = parse_outbound_message(bytes.fromhex('f5 c3 11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'))

        # Assert
        self.assertEqual(command, Command.EW)

        self.assertIsInstance(wcc, WCC)
        self.assertEqual(wcc.value, 0xc3)

        self.assertEqual([order[0] for order in orders], [Order.SBA, Order.SF, None])

    def test_read_modified(self):
        self.assertEqual(parse_outbound_message(bytes.fromhex('06')), (Command.RM,))

    def test_sna_read_modified(self):
        self.assertEqual(parse_outbound_message(bytes.fromhex('f6')), (Command.RM,))

    def test_erase_write_alternate(self):
        # Act
        (command, wcc, orders) = parse_outbound_message(bytes.fromhex('0d c3 11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'))

        # Assert
        self.assertEqual(command, Command.EWA)

        self.assertIsInstance(wcc, WCC)
        self.assertEqual(wcc.value, 0xc3)

        self.assertEqual([order[0] for order in orders], [Order.SBA, Order.SF, None])

    def test_sna_erase_write_alternate(self):
        # Act
        (command, wcc, orders) = parse_outbound_message(bytes.fromhex('7e c3 11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4'))

        # Assert
        self.assertEqual(command, Command.EWA)

        self.assertIsInstance(wcc, WCC)
        self.assertEqual(wcc.value, 0xc3)

        self.assertEqual([order[0] for order in orders], [Order.SBA, Order.SF, None])

    def test_read_modified_all(self):
        self.assertEqual(parse_outbound_message(bytes.fromhex('0e')), (Command.RMA,))

    def test_sna_read_modified_all(self):
        self.assertEqual(parse_outbound_message(bytes.fromhex('63')), (Command.RMA,))

    def test_erase_all_unprotected(self):
        self.assertEqual(parse_outbound_message(bytes.fromhex('0f')), (Command.EAU,))

    def test_sna_all_unprotected(self):
        self.assertEqual(parse_outbound_message(bytes.fromhex('6f')), (Command.EAU,))

    def test_write_structured_field(self):
        # Act
        (command, structured_fields) = parse_outbound_message(bytes.fromhex('11 00 07 01 01 02 03 04 00 00 02 05 06 07'))

        # Assert
        self.assertEqual(command, Command.WSF)

        self.assertEqual([field[0] for field in structured_fields], [1, 2])

    def test_sna_write_structured_field(self):
        # Act
        (command, structured_fields) = parse_outbound_message(bytes.fromhex('f3 00 07 01 01 02 03 04 00 00 02 05 06 07'))

        # Assert
        self.assertEqual(command, Command.WSF)

        self.assertEqual([field[0] for field in structured_fields], [1, 2])

    def test_unrecognized_command(self):
        with self.assertRaisesRegex(ValueError, 'Unrecognized command 0x99'):
            parse_outbound_message(bytes.fromhex('99'))

class FormatInboundReadModifiedMessageTestCase(unittest.TestCase):
    def test_enter(self):
        # Act
        bytes_ = format_inbound_read_modified_message(AID.ENTER, 800, [(Order.SBA, [10]), (None, bytes.fromhex('00 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4 00'))])

        # Assert
        self.assertEqual(bytes_, bytes.fromhex('7d 4c 60 11 40 4a 00 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4 00'))

    def test_clear(self):
        # Act
        bytes_ = format_inbound_read_modified_message(AID.CLEAR, 800, [(Order.SBA, [10]), (None, bytes.fromhex('00 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4 00'))])

        # Assert
        self.assertEqual(bytes_, bytes.fromhex('6d'))

    def test_clear_with_all(self):
        # Act
        bytes_ = format_inbound_read_modified_message(AID.CLEAR, 800, [(Order.SBA, [10]), (None, bytes.fromhex('00 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4 00'))], all_=True)

        # Assert
        self.assertEqual(bytes_, bytes.fromhex('6d 4c 60 11 40 4a 00 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4 00'))

    # TODO: Separate strip nulls test?

    # TODO: Multiple fields

class ParseOrdersTestCase(unittest.TestCase):
    def test(self):
        # Act
        orders = list(parse_orders(bytes.fromhex('11 4b f0 1d f8 c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4')))

        # Assert
        self.assertEqual(orders[0], (Order.SBA, [752]))

        self.assertEqual(orders[1][0], Order.SF)

        self.assertIsInstance(orders[1][1][0], Attribute)
        self.assertEqual(orders[1][1][0].value, 0xf8)

        self.assertEqual(orders[2], (None, bytes.fromhex('c8 c5 d3 d3 d6 40 e6 d6 d9 d3 c4')))

    def test_program_tab(self):
        self.assertEqual(list(parse_orders(bytes.fromhex('05'))), [(Order.PT, None)])

    def test_graphic_escape(self):
        self.assertEqual(list(parse_orders(bytes.fromhex('08 ad'))), [(Order.GE, [0xad])])
    
    def test_set_buffer_address(self):
        self.assertEqual(list(parse_orders(bytes.fromhex('11 4b f0'))), [(Order.SBA, [752])])

    def test_erase_unprotected_to_address(self):
        self.assertEqual(list(parse_orders(bytes.fromhex('12 4b f0'))), [(Order.EUA, [752])])

    def test_insert_cursor(self):
        self.assertEqual(list(parse_orders(bytes.fromhex('13'))), [(Order.IC, None)])

    def test_start_field(self):
        # Act
        orders = list(parse_orders(bytes.fromhex('1d f8')))

        # Assert
        self.assertEqual(orders[0][0], Order.SF)

        self.assertIsInstance(orders[0][1][0], Attribute)
        self.assertEqual(orders[0][1][0].value, 0xf8)

    def test_set_attribute(self):
        # Act
        orders = list(parse_orders(bytes.fromhex('28 41 f2')))

        # Assert
        self.assertEqual(orders[0][0], Order.SA)

        self.assertIsInstance(orders[0][1][0], HighlightExtendedAttribute)
        self.assertTrue(orders[0][1][0].reverse)

    def test_start_field_extended(self):
        # Act
        orders = list(parse_orders(bytes.fromhex('29 02 c0 60 42 f1')))

        # Assert
        self.assertEqual(orders[0][0], Order.SFE)

        self.assertIsInstance(orders[0][1][0], Attribute)
        self.assertEqual(orders[0][1][0].value, 0x60)

        extended_attributes = orders[0][1][1]

        self.assertEqual(len(extended_attributes), 1)

        self.assertIsInstance(extended_attributes[0], ForegroundColorExtendedAttribute)
        self.assertEqual(extended_attributes[0].color, 0xf1)

    def test_modify_field(self):
        # Act
        orders = list(parse_orders(bytes.fromhex('2c 02 c0 60 42 f1')))

        # Assert
        self.assertEqual(orders[0][0], Order.MF)

        self.assertIsInstance(orders[0][1][0], Attribute)
        self.assertEqual(orders[0][1][0].value, 0x60)

        extended_attributes = orders[0][1][1]

        self.assertEqual(len(extended_attributes), 1)

        self.assertIsInstance(extended_attributes[0], ForegroundColorExtendedAttribute)
        self.assertEqual(extended_attributes[0].color, 0xf1)

    def test_repeat_to_address(self):
        self.assertEqual(list(parse_orders(bytes.fromhex('3c 4b f0 c1'))), [(Order.RA, [752, 0xc1, False])])

    def test_repeat_to_address_graphic_escape(self):
        self.assertEqual(list(parse_orders(bytes.fromhex('3c 4b f0 08 ad'))), [(Order.RA, [752, 0xad, True])])

class ParseOutboundStructuredFieldsTestCase(unittest.TestCase):
    def test(self):
        self.assertEqual(list(parse_outbound_structured_fields(bytes.fromhex('00 07 01 01 02 03 04 00 00 02 05 06 07'))), [(1, bytes.fromhex('01 02 03 04')), (2, bytes.fromhex('05 06 07'))])

    def test_invalid_field(self):
        for bytes_ in [bytes.fromhex('01'), bytes.fromhex('01 02')]:
            with self.subTest(bytes_=bytes_):
                with self.assertRaises(Exception):
                    list(parse_outbound_structured_fields(bytes_))

    def test_invalid_length(self):
        for bytes_ in [bytes.fromhex('00 02 01 01'), bytes.fromhex('00 05 01 01')]:
            with self.subTest(bytes_=bytes_):
                with self.assertRaises(Exception):
                    list(parse_outbound_structured_fields(bytes_))

class FormatInboundStructuredFieldsTestCase(unittest.TestCase):
    def test(self):
        # Act
        bytes_ = format_inbound_structured_fields([(0x81, bytes.fromhex('80 80'))])

        # Assert
        self.assertEqual(bytes_, bytes.fromhex('88 00 05 81 80 80'))

class ParseExtendedAttributeTestCase(unittest.TestCase):
    def test_highlight(self):
        extended_attribute = parse_extended_attribute(bytes.fromhex('41 f2'))

        self.assertIsInstance(extended_attribute, HighlightExtendedAttribute)

    def test_foreground_color(self):
        extended_attribute = parse_extended_attribute(bytes.fromhex('42 00'))

        self.assertIsInstance(extended_attribute, ForegroundColorExtendedAttribute)

    def test_unsupported(self):
        extended_attribute = parse_extended_attribute(bytes.fromhex('43 00'))

        self.assertIsInstance(extended_attribute, ExtendedAttribute)

        self.assertEqual(extended_attribute.type_, 0x43)
        self.assertEqual(extended_attribute.value, 0x00)

    def test_invalid(self):
        with self.assertRaises(Exception):
            parse_extended_attribute(bytes.fromhex('00'))

class ParseAddressTestCase(unittest.TestCase):
    def test_12_bit_address_with_01_prefix(self):
        (address, size) = parse_address(bytes([0b01000000, 0b01111100]))

        self.assertEqual(address, 60)
        self.assertEqual(size, 12)

    def test_12_bit_address_with_11_prefix(self):
        (address, size) = parse_address(bytes([0b11000010, 0b01100000]))

        self.assertEqual(address, 160)
        self.assertEqual(size, 12)

    def test_14_bit_address(self):
        (address, size) = parse_address(bytes([0b00000011, 0b00100000]))

        self.assertEqual(address, 800)
        self.assertEqual(size, 14)

    def test_16_bit_address(self):
        (address, size) = parse_address(bytes([0b00001100, 0b00011100]), size=16)

        self.assertEqual(address, 3100)
        self.assertEqual(size, 16)

class FormatAddressTestCase(unittest.TestCase):
    def test_12_bit_address(self):
        self.assertEqual(format_address(160, size=12), bytes([0b11000010, 0b01100000]))

    def test_14_bit_address(self):
        self.assertEqual(format_address(800, size=14), bytes([0b00000011, 0b00100000]))

    def test_16_bit_address(self):
        self.assertEqual(format_address(3100, size=16), bytes([0b00001100, 0b00011100]))

    def test_invalid_size(self):
        with self.assertRaisesRegex(ValueError, 'Invalid size'):
            format_address(3100, size=13)
