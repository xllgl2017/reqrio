package org.xllgl2017;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

public class Headers {
    private String uri;
    private Method method;
    private int status;
    private String agreement;
    private final List<Header> keys;
    private final List<Cookie> cookies;

    public Headers() {
        this.keys = new ArrayList<>();
        this.cookies = new ArrayList<>();
    }

    public Headers(JsonObject header) {
        this.uri = header.get("uri").toString();
        Gson gson = new Gson();
        this.method = gson.fromJson(header.get("method").getAsString(), Method.class);
        this.status = header.get("status").getAsInt();
        this.agreement = header.get("agreement").toString();
        this.keys = new ArrayList<>();
        this.cookies = new ArrayList<>();
        JsonObject ks = header.get("keys").getAsJsonObject();

        for (String k : ks.keySet()) {
            if (k.startsWith("HTTP/")) continue;
            if (k.equalsIgnoreCase("set-cookie")) {
                JsonArray cookies = ks.getAsJsonArray(k);
                for (JsonElement cookie : cookies) {
                    this.cookies.add(gson.fromJson(cookie, Cookie.class));
                }
            } else {
                this.keys.add(new Header(k, ks.get(k).getAsString()));
            }
        }
    }

    public void addHeader(Header header) {
        this.keys.add(header);
    }

    public void addHeader(String name, String value) {
        this.keys.add(new Header(name, value));
    }

    public List<Cookie> getCookies() {
        return cookies;
    }

    public void addCookie(Cookie cookie) {
        this.cookies.add(cookie);
    }

    public void setCookies(String cookies) {
        String[] items = cookies.split("; ");
        for (String item : items) {
            String[] kvs = item.split("=");
            if (kvs.length > 1) {
                this.addCookie(new Cookie(kvs[0], kvs[1]));
            } else {
                this.addCookie(new Cookie(kvs[0], ""));
            }
        }
    }

    public List<Header> getKeys() {
        return keys;
    }
}
