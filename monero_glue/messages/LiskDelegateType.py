# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p


class LiskDelegateType(p.MessageType):

    def __init__(
        self,
        username: str = None,
    ) -> None:
        self.username = username

    @classmethod
    def get_fields(cls):
        return {
            1: ('username', p.UnicodeType, 0),
        }
