import json

from reqrio.header import Header


class Response:
    def __init__(self, resp: dict):
        self.header = Header(resp["header"])
        self.raw = bytes.fromhex(resp["body"])
        del resp
        return

    def json(self) -> dict:
        return json.loads(self.raw.decode('utf-8'))

    def text(self) -> str:
        return self.raw.decode('utf-8')

