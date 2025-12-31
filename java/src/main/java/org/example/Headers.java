package org.example;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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

    public List<Cookie> getCookies() {
        return cookies;
    }

    public void add_cookie(Cookie cookie) {
        this.cookies.add(cookie);
    }

}
