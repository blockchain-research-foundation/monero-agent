# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p


class TezosAddress(p.MessageType):
    MESSAGE_WIRE_TYPE = 151
    FIELDS = {
        1: ('address', p.UnicodeType, 0),
    }

    def __init__(
        self,
        address: str = None,
    ) -> None:
        self.address = address