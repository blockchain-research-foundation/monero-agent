# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .TezosContractID import TezosContractID


class TezosDelegationOp(p.MessageType):
    FIELDS = {
        1: ('source', TezosContractID, 0),
        2: ('fee', p.UVarintType, 0),
        3: ('counter', p.UVarintType, 0),
        4: ('gas_limit', p.UVarintType, 0),
        5: ('storage_limit', p.UVarintType, 0),
        6: ('delegate', p.BytesType, 0),
    }

    def __init__(
        self,
        source: TezosContractID = None,
        fee: int = None,
        counter: int = None,
        gas_limit: int = None,
        storage_limit: int = None,
        delegate: bytes = None,
    ) -> None:
        self.source = source
        self.fee = fee
        self.counter = counter
        self.gas_limit = gas_limit
        self.storage_limit = storage_limit
        self.delegate = delegate