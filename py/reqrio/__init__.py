import json
import os
from ctypes import *
from enum import Enum

from reqrio.response import Response


def _load_dll() -> CDLL:
    base = os.path.dirname(__file__)
    dll_path = os.path.join(base, 'reqrio.dll')
    os.add_dll_directory(base)
    return cdll.LoadLibrary(dll_path)


class ALPN(Enum):
    HTTP10 = "http/1.0"
    HTTP11 = "http/1.1"
    HTTP20 = "h2"


class Session:
    # alpn值是字符串['http/1.1','h2']
    def __init__(self, alpn: ALPN = ALPN.HTTP11):
        self.dll = _load_dll()
        # self.dll = cdll.LoadLibrary(r"D:\projects\rust\reqrio\target\debug\reqrio.dll")
        # 初始化函数
        self.dll.init_http.restype = c_int

        self.dll.set_header_json.argtypes = [c_int, c_char_p]
        self.dll.set_header_json.restype = c_int

        self.dll.add_header.argtypes = [c_int, c_char_p, c_char_p]
        self.dll.add_header.restype = c_int

        self.dll.set_alpn.argtypes = [c_int, c_char_p]
        self.dll.set_alpn.restype = c_int

        self.dll.set_fingerprint.argtypes = [c_int, c_char_p]
        self.dll.set_fingerprint.restype = c_int

        self.dll.set_ja3.argtypes = [c_int, c_char_p]
        self.dll.set_ja3.restype = c_int

        self.dll.set_proxy.argtypes = [c_int, c_char_p]
        self.dll.set_proxy = c_int

        self.dll.set_url.argtypes = [c_int, c_char_p]
        self.dll.set_url.restype = c_int

        self.dll.set_data.argtypes = [c_int, c_char_p]
        self.dll.set_data.restype = c_int

        self.dll.set_json.argtypes = [c_int, c_char_p]
        self.dll.set_json.restype = c_int

        self.dll.add_param.argtypes = [c_int, c_char_p]
        self.dll.add_param.restype = c_int

        self.dll.get.argtypes = [c_int]
        self.dll.get.restype = c_void_p

        self.dll.post.argtypes = [c_int]
        self.dll.post.restype = c_void_p

        self.dll.options.argtypes = [c_int]
        self.dll.options.restype = c_void_p

        self.dll.put.argtypes = [c_int]
        self.dll.put.restype = c_void_p

        self.dll.head.argtypes = [c_int]
        self.dll.head.restype = c_void_p

        self.dll.trach.argtypes = [c_int]
        self.dll.trach.restype = c_void_p

        self.dll.destroy.argtypes = [c_int]

        self.dll.free_pointer.argtypes = [c_void_p]

        self.hid = self.dll.init_http()
        if self.hid == -1: raise Exception('init fail')
        r = self.dll.set_alpn(self.hid, alpn.value.encode('utf-8'))
        if r == -1: raise Exception('set alpn error')

    def set_header_json(self, header: dict):
        r = self.dll.set_header_json(self.hid, json.dumps(header).encode('utf-8'))
        if r == -1: raise Exception('set header error')

    def add_header(self, name: str, value: str):
        r = self.dll.set_header_json(self.hid, name.encode('utf-8'), value.encode('utf-8'))
        if r == -1: raise Exception('add header error')

    def set_fingerprint(self, fingerprint: str):
        """指纹数据，是tls握手过程中客户端发出的数据（转十六进制）,包含:

        1.client_hello

        2.client_key_exchange

        3.change_cipher_spec"""
        r = self.dll.set_fingerprint(self.hid, fingerprint.encode('utf-8'))
        if r == -1: raise Exception('set fingerprint error')

    def set_ja3(self, ja3: str):
        r = self.dll.set_ja3(self.hid, ja3.encode('utf-8'))
        if r == -1: raise Exception('set ja3 error')

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

    def add_param(self, name: str, value: str):
        r = self.dll.add_param(self.hid, name.encode('utf-8'), value.encode('utf-8'))
        if r == -1: raise Exception('add param error')

    def get(self) -> Response:
        resp = self.dll.get(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def post(self) -> Response:
        resp = self.dll.post(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def options(self) -> Response:
        resp = self.dll.options(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def put(self) -> Response:
        resp = self.dll.put(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def head(self) -> Response:
        resp = self.dll.head(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def delete(self) -> Response:
        resp = self.dll.delete(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def trach(self) -> Response:
        resp = self.dll.trach(self.hid)
        bs = string_at(resp).decode('utf-8')
        self.dll.free_pointer(resp)
        try:
            resp = json.loads(bytes.fromhex(bs))
            return Response(resp)
        except Exception as _:
            raise Exception(bs)

    def close(self):
        """记得关闭资源，否则容易造成内存溢出"""
        self.dll.destroy(self.hid)
