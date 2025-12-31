package org.example;

import com.sun.jna.Pointer;
import org.apache.commons.codec.DecoderException;

public class Reqrio {
    private final ReqrioLibrary lib;
    private int hid = -1;

    public Reqrio() {
        this.lib = ReqrioLibrary.INSTANCE;
        this.hid = this.lib.init_http();
    }

    public void setHeaderJson(String header) throws Exception {
        int res = this.lib.set_header_json(this.hid, header);
        if (res == -1) throw new Exception("set header json error");
    }

    public void addHeader(Header header) throws Exception {
        int res = this.lib.add_header(this.hid, header.getName(), header.getValue());
        if (res == -1) throw new Exception("add header error");
    }

    public void setALPN(ALPN alpn) throws Exception {
        int res = this.lib.set_alpn(this.hid, alpn.get_value());
        if (res == -1) throw new Exception("set alpn error");
    }

    public void setProxy(String proxy) throws Exception {
        int res = this.lib.set_proxy(this.hid, proxy);
        if (res == -1) throw new Exception("set alpn error");
    }

    void setUrl(String url) throws Exception {
        int res = this.lib.set_url(this.hid, url);
        if (res == -1) throw new Exception("set url error");
    }

    public void addParam(String name, String value) throws Exception {
        int res = this.lib.add_param(this.hid, name, value);
        if (res == -1) throw new Exception("add param error");
    }

    public void setData(String data) throws Exception {
        int res = this.lib.set_data(this.hid, data);
        if (res == -1) throw new Exception("set data error");
    }

    public void setJson(String json) throws Exception {
        int res = this.lib.set_json(this.hid, json);
        if (res == -1) throw new Exception("set data error");
    }

    public void setContentType(String content_type) throws Exception {
        int res = this.lib.set_content_type(this.hid, content_type);
        if (res == -1) throw new Exception("set content_type error");
    }

    public void setCookie(String cookie) throws Exception {
        int res = this.lib.set_cookie(this.hid, cookie);
        if (res == -1) throw new Exception("set cookie error");
    }

    public void addCookie(String name, String value) throws Exception {
        int res = this.lib.add_cookie(this.hid, name, value);
        if (res == -1) throw new Exception("add cookie error");
    }

    public void setTimeout(Timeout timeout) throws Exception {
        int res = this.lib.set_timeout(this.hid, "");
        if (res == -1) throw new Exception("set timeout error");
    }

    public void setBytes(byte[] bytes) throws Exception {
        int res = this.lib.set_bytes(this.hid, bytes, bytes.length);
        if (res == -1) throw new Exception("set bytes error");
    }

    public Response send(Method method) throws DecoderException {
        Pointer ptr = switch (method) {
            case GET -> this.lib.get(this.hid);
            case POST -> this.lib.post(this.hid);
            case PUT -> this.lib.put(this.hid);
            case OPTIONS -> this.lib.options(this.hid);
            case DELETE -> this.lib.delete(this.hid);
            case HEAD -> this.lib.head(this.hid);
            case TRACH -> this.lib.trach(this.hid);
        };
        String hex_res = ptr.getString(0);
        Response response = new Response(hex_res);
        this.lib.free_pointer(ptr);
        return response;
    }

    public Response get(String url) throws Exception {
        this.setUrl(url);
        return this.send(Method.GET);
    }

    public Response post(String url) throws Exception {
        this.setUrl(url);
        return this.send(Method.POST);
    }

    public Response put(String url) throws Exception {
        this.setUrl(url);
        return this.send(Method.PUT);
    }

    public Response options(String url) throws Exception {
        this.setUrl(url);
        return this.send(Method.OPTIONS);
    }

    public Response head(String url) throws Exception {
        this.setUrl(url);
        return this.send(Method.HEAD);
    }

    public Response delete(String url) throws Exception {
        this.setUrl(url);
        return this.send(Method.DELETE);
    }

    public Response trach(String url) throws Exception {
        this.setUrl(url);
        return this.send(Method.TRACH);
    }

    public void destroy() {
        this.lib.destroy(this.hid);
    }


}
