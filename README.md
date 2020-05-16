# pytn3270

Python TN3270 library.

Inspired by [pyte](https://github.com/selectel/pyte), this is a pure Python TN3270 library providing data stream parsing and in-memory emulation. It does not include a user interface or routines to support automation, instead it is designed to be used to build user-facing emulators and automation libraries.

## Features

pytn3270 is a work in progress and only supports basic TN3270 emulation.

## Usage

Install using `pip`:

```
pip install pytn3270
```

Connect to a mainframe:

```
from tn3270 import Telnet, Emulator, AID, CharacterCell

telnet = Telnet('IBM-3278-2')

telnet.open('mainframe', 23)

emulator = Emulator(telnet, 24, 80)

# Wait until the keyboard is unlocked.
while emulator.keyboard_locked:
    print('Waiting for keyboard to be unlocked...')

    emulator.update(timeout=1)

# Convert the screen contents to a string, replacing attribute cells with '@'.
#
# Note that this is not supposed to demonstrate an efficient implementation.
screen = ''

for cell in emulator.cells:
    if isinstance(cell, CharacterCell):
        byte = cell.byte

        if byte == 0:
            screen += ' '
        else:
            screen += bytes([byte]).decode('cp500')
    else:
        screen += '@'

# Display the screen.
for line in [screen[index:index+80] for index in range(0, len(screen), 80)]:
    print(line)
```

## References

If you are looking for information on the TN3270 protocol I'd recommend the
following resources:

  * Steve Millington's [TN3270 Protocol Cheat Sheet](http://ruelgnoj.co.uk/3270/)

For information on the 3270 data stream (as used by TN3270) I'd recommend:

  * IBM [3270 Data Stream Programmer's Reference](https://bitsavers.computerhistory.org/pdf/ibm/3270/GA23-0059-4_3270_Data_Stream_Programmers_Reference_Dec88.pdf) (GA23-0059-4)
  * IBM CICS [The 3270 Family of Terminals](https://www.ibm.com/support/knowledgecenter/en/SSGMGV_3.1.0/com.ibm.cics.ts31.doc/dfhp3/dfhp3bg.htm#DFHP3BG)
  * Greg Price's [3270 Programming Overview](http://www.prycroft6.com.au/misc/3270.html)
  * Tommy Sprinkles' [3270 Data Stream Programming](https://www.tommysprinkle.com/mvs/P3270/start.htm)

## See Also

* [oec](https://github.com/lowobservable/oec) - IBM 3270 terminal controller
