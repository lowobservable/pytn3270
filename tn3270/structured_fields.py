"""
tn3270.structured_fields
~~~~~~~~~~~~~~~~~~~~~~~~
"""

from enum import Enum, IntEnum

class StructuredField(IntEnum):
    READ_PARTITION = 0x01
    QUERY_REPLY = 0x81

class ReadPartitionType(IntEnum):
    QUERY = 0x02

class QueryReply(IntEnum):
    SUMMARY = 0x80
