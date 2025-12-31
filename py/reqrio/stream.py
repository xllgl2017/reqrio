from queue import Queue
from threading import Thread

from _queue import Empty

from reqrio.session import Session
from reqrio.method import Method


class Stream:
    def __init__(self, session: Session, method: Method):
        self.session = session
        self.q = Queue()
        self._cb = session.callback(self._callback)
        self.thread = Thread(target=self.__start_stream)
        self.method = method
        self.response = None
        self.start()

    def __start_stream(self):
        if self.method == Method.GET:
            self.response = self.session.get()
        elif self.method == Method.POST:
            self.response = self.session.get()
        elif self.method == Method.PUT:
            self.response = self.session.put()
        elif self.method == Method.HEAD:
            self.response = self.session.head()
        elif self.method == Method.OPTIONS:
            self.response = self.session.options(),
        elif self.method == Method.TRACH:
            self.response = self.session.trach()

    # 这个是 ctypes 回调
    def _callback(self, p, l):
        data = bytes(p[:l])
        self.q.put(data)
        return 0

    # 开始接收数据
    def start(self):
        r = self.session.dll.register(self.session.hid, self._cb)
        if r != 0:
            raise RuntimeError("register failed")
        self.thread.start()
        return self

    def __iter__(self):
        return self

    def __next__(self):
        if not self.thread.is_alive():
            raise StopIteration
        try:
            item = self.q.get(timeout=0.1)
        except Empty:
            return self.__next__()
        return item