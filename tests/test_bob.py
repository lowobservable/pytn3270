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

        self.emulator = Emulator(self.stream, 43, 80)

    def test_write(self):
        # Arrange
        self.stream.read_multiple = Mock(return_value=[bytearray(b'~\xc3\x11\\\xf5\x13\x11@@\x1d\xf0\xc9\xc5\xe2\xc1\xc4\xd4\xe2\xd3K\xc9\xc5\xe2\xc5\xc1\xc4\xd4@\x1d\xf8@@@@@@@@\xe5\xe2\xc5a\xc5\xe2\xc1@\xc6\xe4\xd5\xc3\xe3\xc9\xd6\xd5@\xe2\xc5\xd3\xc5\xc3\xe3\xc9\xd6\xd5@@@@@@@@@@@@@@@@@@@@@@@@@@\x1d\xf0\x11\xc2N\x1d\xf0\xc1\xd7\xd7\xd3\xc9\xc4z\x1d\xf8\xc4\xc2\xc4\xc3\xc3\xc9\xc3\xe2\x1d\xf0\x11\xc2\xe2\x1d\xf0\xc5\x95\xa3\x85\x99@\xa3\x88\x85@\x95\xa4\x94\x82\x85\x99@\x96\x86@\xa8\x96\xa4\x99@\xa2\x85\x93\x85\x83\xa3\x89\x96\x95@\x81\x95\x84@\x97\x99\x85\xa2\xa2@\xa3\x88\x85@\xc5\xd5\xe3\xc5\xd9@\x92\x85\xa8z\x11\xc5\xc8\x1d\xf8\xf1\x1d\xf0\x1d\xf0\xc9\x95\xa2\xa3\x81\x93\x93\x81\xa3\x89\x96\x95\x05\x11\xc6J\x1d\xf0\x11\xc6\xd8\x1d\xf8\xf2\x1d\xf0\x1d\xf0\xd9\x85\xa2\x96\xa4\x99\x83\x85@\xc4\x85\x86\x89\x95\x89\xa3\x89\x96\x95\x05\x11\xc7Z\x1d\xf0\x11\xc7\xe8\x1d\xf8\xf3\x1d\xf0\x1d\xf0\xd6\x97\x85\x99\x81\xa3\x89\x96\x95\xa2\x05\x11\xc8j\x1d\xf0\x11\xc8\xf8\x1d\xf8\xf4\x1d\xf0\x1d\xf0\xd7\x99\x96\x82\x93\x85\x94@\xc8\x81\x95\x84\x93\x89\x95\x87\x05\x11\xc9z\x1d\xf0\x11J\xc8\x1d\xf8\xf5\x1d\xf0\x1d\xf0\xd7\x99\x96\x87\x99\x81\x94@\xc4\x85\xa5\x85\x93\x96\x97\x94\x85\x95\xa3\x05\x11KJ\x1d\xf0\x11K\xd8\x1d\xf8\xf6\x1d\xf0\x1d\xf0\xc3\x96\x94\x94\x81\x95\x84@\xd4\x96\x84\x85\x05\x11LZ\x1d\xf0\x11L\xe8\x1d\xf8\xf7\x1d\xf0\x1d\xf0\xc3\xc9\xc3\xe2`\xe2\xa4\x97\x97\x93\x89\x85\x84@\xe3\x99\x81\x95\xa2\x81\x83\xa3\x89\x96\x95\xa2\x05\x11Mj\x1d\xf0\x11M\xf8\x1d\xf8@\x1d\xf0\x1d\xf0@@\x05\x11Nz\x1d\xf0\x11O\xc8\x1d\xf8@\x1d\xf0\x1d\xf0@@\x05\x11PJ\x1d\xf0\x11\xd1`\x1d|@@@\xc1@\xe6\xc1\xd9\xd5\x89\x95\x87@\x88\x81\xa2@\x82\x85\x85\x95@\x89\xa2\xa2\xa4\x85\x84@\xa3\x96@\xa2\x89\x87\x95\x81\x93@\xa3\x88\x81\xa3@\xc9\xc3\xc3\xc6@\xa2\x88\xa4\xa3@\x84\x96\xa6\x95@\xa6\x89\x93\x93@\xa2\x96\x96\x95@\x96\x83\x83\xa4\x99K@@@\x1d\xf0\x1d|\xe3\x88\x85\x99\x85@\x89\xa2@\x81\xa3@\x93\x85\x81\xa2\xa3@\x96\x95\x85@\x94\x85\xa2\xa2\x81\x87\x85@\xa6\x81\x89\xa3\x89\x95\x87@\x86\x96\x99@\xa8\x96\xa4@\xa3\x96@\x99\x85\xa3\x99\x89\x85\xa5\x85@\x89\xa3K@@@@@@@@@@@@@@@@@\x1d\xf0\x1d\xf8\xe3\x88\x89\xa2@\x89\xa2@\x95\x85\xa6@\x95\x85\xa6\xa2@\xa3\x88\x81\xa3@\xa8\x96\xa4@\x83\x81\x95@\xa4\xa2\x85Z@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\x1d\xf0\x1d\xf8@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\x1d\xf0\x1d\xf8@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\x1d\xf0\x1d\xf8@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\x1d\xf0\x1d\xf0\xd7\xc6\xf1~\xc8\xc5\xd3\xd7\x11\xd9\\\x1d\xf0\xf3~\xe2\xc9\xc7\xd5@\xd6\xc6\xc6@@\x1d|\xf4~\xd9\xc5\xe3\xe4\xd9\xd5@@@@\x1d|\xf5~\xd9\xc5\xc2\xe4\xc9\xd3\xc4@@@\x1d\xf0\xf6~\xc5\xe2\xc3\xc1\xd7\xc5M\xe4]@\x1d\xf0\x11Zl\x1d\xf0\xf9~\xc5\xa2\x83\x81\x97\x85M\x94]@\x1d\xf0\x11[`\x1d\xf8\x11\\o\x1d\xf0\x1d\xf8~~n\x1d\xc1\x11]\xc9\x1d\xf0\x11]a\x1d|@@@\xd7\x81\xa3\x88z\x1d\xf0\x11]\xf7\x1d\xf0')])

        # Act and assert
        self.assertTrue(self.emulator.update())