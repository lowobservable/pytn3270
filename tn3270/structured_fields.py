"""
tn3270.structured_fields
~~~~~~~~~~~~~~~~~~~~~~~~
"""

from enum import Enum, IntEnum

class StructuredField(IntEnum):
    READ_PARTITION = 0x01
    OUTBOUND_3270DS = 0x40
    QUERY_REPLY = 0x81

class ReadPartitionType(IntEnum):
    QUERY = 0x02
    QUERY_LIST = 0x03

class QueryListRequestType(IntEnum):
    LIST = 0x00
    EQUIVALENT_AND_LIST = 0x40
    ALL = 0x80

class QueryCode(IntEnum):
    SUMMARY = 0x80
    USABLE_AREA = 0x81
    ALPHANUMERIC_PARTITIONS = 0x84
    REPLY_MODES = 0x88
    IMPLICIT_PARTITIONS = 0xa6
    NULL = 0xff
