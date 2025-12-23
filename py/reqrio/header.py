class Cookie:
    def __init__(self, cookie: dict):
        self.cookie = cookie['name']
        self.value = cookie['value']
        self.age = cookie['age']
        self.domain = cookie['domain']
        self.path = cookie['path']
        self.httpOnly = cookie['http_only']
        self.secure = cookie['secure']
        self.expires = cookie['expires']
        self.sameSite = cookie['same_site']
        self.icpsp = cookie['icpsp']
        del cookie
        return


class Header:
    def __init__(self, header: dict):
        self.uri = header["uri"]
        self.method = header["method"]
        self.status = header["status"]
        self.agreement = header["agreement"]
        self.keys: dict = header["keys"]
        self.cookies = []
        for cookie in self.keys.get('set-cookie', []):
            self.cookies.append(Cookie(cookie))
        del header
        if self.keys.get("set-cookie") is not None:
            del self.keys['set-cookie']
        return

    def get(self, key: str):
        return self.keys.get(key, None)

    def location(self):
        return self.keys.get("location")
