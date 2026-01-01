import json
from ctypes import *

from reqrio.alpn import ALPN
from reqrio.bindings import DLL, CALLBACK
from reqrio.method import Method
from reqrio.response import Response


class Session:
    # alpn值是字符串['http/1.1','h2']
    def __init__(self, alpn: ALPN = ALPN.HTTP11):
        self.dll = DLL
        self.callback=CALLBACK

        self.hid = self.dll.init_http()
        if self.hid == -1: raise Exception('init fail')
        r = self.dll.set_alpn(self.hid, alpn.value.encode('utf-8'))
        if r == -1: raise Exception('set alpn error')

    def set_timeout(self, connect: int = 3, read: int = 3, write: int = 3, handle: int = 30, connect_times: int = 3,
                    handle_times: int = 3):
        """
        :param connect: 连接超时,默认3s
        :param read: tcp读取超时,默认3s
        :param write: tcp写出超时,默认3s
        :param handle: 发包处理超时,默认30s
        :param connect_times: 尝试连接次数,默认3次
        :param handle_times:尝试处理次数,默认3次
        :return:
        """
        timeout = {
            'connect': connect,
            'read': read,
            'write': write,
            'handle': handle,
            'connect_times': connect_times,
            'handle_times': handle_times,
        }
        r = self.dll.set_timeout(self.hid, json.dumps(timeout).encode('utf-8'))
        if r == -1: raise Exception('set timeout error')
        return

    def set_header_json(self, header: dict):
        r = self.dll.set_header_json(self.hid, json.dumps(header).encode('utf-8'))
        if r == -1: raise Exception('set header error')

    def add_header(self, name: str, value: str):
        r = self.dll.set_header_json(self.hid, name.encode('utf-8'), value.encode('utf-8'))
        if r == -1: raise Exception('add header error')

    # def set_fingerprint(self, fingerprint: str):
    #     """指纹数据，是tls握手过程中客户端发出的数据（转十六进制）,包含:
    #
    #     1.client_hello
    #
    #     2.client_key_exchange
    #
    #     3.change_cipher_spec"""
    #     r = self.dll.set_fingerprint(self.hid, fingerprint.encode('utf-8'))
    #     if r == -1: raise Exception('set fingerprint error')

    # def set_ja3(self, ja3: str):
    #     r = self.dll.set_ja3(self.hid, ja3.encode('utf-8'))
    #     if r == -1: raise Exception('set ja3 error')

    def set_proxy(self, proxy: str):
        """设置代理，格式:http://127.0.0.1:10000、socks5://127.0.0.1:10001"""
        r = self.dll.set_proxy(self.hid, proxy.encode('utf-8'))
        if r == -1: raise Exception('set proxy error')

    def set_url(self, url: str):
        r = self.dll.set_url(self.hid, url.encode('utf-8'))
        if r == -1: raise Exception('set url error')

    def set_data(self, data: dict):
        r = self.dll.set_data(self.hid, json.dumps(data).encode('utf-8'))
        if r == -1: raise Exception('set data error')

    def set_json(self, data: dict):
        r = self.dll.set_json(self.hid, json.dumps(data).encode('utf-8'))
        if r == -1: raise Exception('set json error')

    def set_bytes(self, bytes: bytes):
        r = self.dll.set_bytes(self.hid, bytes, len(bytes))
        if r == -1: raise Exception('set bytes error')

    def set_content_type(self, content_type: str):
        r = self.dll.set_content_type(self.hid, content_type.encode('utf-8'))
        if r == -1: raise Exception('set content_type error')

    def set_cookie(self, cookie: str):
        r = self.dll.set_cookie(self.hid, cookie.encode('utf-8'))
        if r == -1: raise Exception('set json error')

    def add_cookie(self, name: str, value: str):
        r = self.dll.add_cookie(self.hid, name.encode('utf-8'), value.encode('utf-8'))
        if r == -1: raise Exception('set json error')

    def set_params(self, param: dict):
        for k in param.keys():
            self.add_param(k, str(param[k]))
        return

    def add_param(self, name: str, value: str):
        r = self.dll.add_param(self.hid, name.encode('utf-8'), value.encode('utf-8'))
        if r == -1: raise Exception('add param error')

    def get(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        resp = self.dll.get(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def post(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        resp = self.dll.post(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def options(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        resp = self.dll.options(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def put(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        resp = self.dll.put(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def head(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        resp = self.dll.head(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def delete(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        resp = self.dll.delete(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def trach(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        resp = self.dll.trach(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def open_stream(self, url: str, method: Method):
        from reqrio.stream import Stream

        self.set_url(url)
        return Stream(self, method)

    def close(self):
        """记得关闭资源，否则容易造成内存溢出"""
        self.dll.destroy(self.hid)
