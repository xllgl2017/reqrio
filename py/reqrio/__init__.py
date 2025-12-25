from reqrio.response import Response
from reqrio.session import Session
from reqrio.alpn import ALPN


def get(url: str, headers: dict, params: dict = None, data: dict = None, json: dict = None,
        alpn=ALPN.HTTP11) -> Response:
    s = Session(alpn)
    s.set_url(url)
    if params is not None:
        for k in params.keys():
            s.add_param(k, str(params[k]))

    if data is not None:
        s.set_data(data)

    if json is not None:
        s.set_json(json)

    s.set_header_json(headers)
    resp = s.get()
    s.close()
    return resp


def post(url: str, headers: dict, params: dict = None, data: dict = None, json: dict = None,
         alpn=ALPN.HTTP11) -> Response:
    s = Session(alpn)
    s.set_url(url)
    if params is not None:
        for k in params.keys():
            s.add_param(k, str(params[k]))

    if data is not None:
        s.set_data(data)

    if json is not None:
        s.set_json(json)

    s.set_header_json(headers)

    resp = s.post()
    s.close()
    return resp
