# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p


class TronTransferContract(p.MessageType):
    FIELDS = {
        1: ('to_address', p.BytesType, 0),
        2: ('amount', p.UVarintType, 0),
    }

    def __init__(
        self,
        to_address: bytes = None,
        amount: int = None,
    ) -> None:
        self.to_address = to_address
        self.amount = amount
