# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p


class TronAccountUpdateContract(p.MessageType):
    FIELDS = {
        1: ('account_name', p.UnicodeType, 0),
    }

    def __init__(
        self,
        account_name: str = None,
    ) -> None:
        self.account_name = account_name
