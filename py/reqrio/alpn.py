from enum import Enum


class ALPN(Enum):
    HTTP10 = "http/1.0"
    HTTP11 = "http/1.1"
    HTTP20 = "h2"


