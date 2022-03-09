import unittest
from unittest.mock import Mock, create_autospec

import string

import context

from tn3270.telnet import Telnet
from tn3270.emulator import Emulator, AttributeCell, CharacterCell, ProtectedCellOperatorError, FieldOverflowOperatorError
from tn3270.datastream import AID

class BobTestCase(unittest.TestCase):
    def setUp(self):
        self.stream = create_autospec(Telnet, instance=True)

        self.emulator = Emulator(self.stream, 24, 80)

    def test_write(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[

bytearray(b'~\xc2\x11@@\x13'),
bytearray(b'\xf1\xc2\x11O_\x13\x11@\xc9,\x01\xc0|\x11@a,\x01\xc0|\x11O^,\x01\xc0\xc8@\x11\\\xd6,\x01\xc0}')

        ])

        # Act and assert
        self.assertTrue(self.emulator.update())
        self.assertTrue(self.emulator.update())

        # Convert the screen contents to a string, replacing attribute cells with '@'.
        #
        # Note that this is not supposed to demonstrate an efficient implementation.
        screen = ''

        for cell in self.emulator.cells:
            if isinstance(cell, CharacterCell):
                byte = cell.byte

                if byte == 0:
                    screen += ' '
                else:
                    screen += bytes([byte]).decode('ibm037')
            else:
                screen += '@'

        # Display the screen.
        for line in [screen[index:index+80] for index in range(0, len(screen), 80)]:
            print(line)
