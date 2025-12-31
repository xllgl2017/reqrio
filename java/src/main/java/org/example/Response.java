package org.example;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class Response {
    private byte[] body;
    private Headers header;

    public Response(String hex) throws DecoderException {
        byte[] bytes = Hex.decodeHex(hex);
        String str_res = new String(bytes);
        Gson gson = new Gson();
        JsonObject obj = gson.fromJson(str_res, JsonObject.class);
        JsonObject header = obj.get("header").getAsJsonObject();
        IO.println(obj);
        this.header = new Headers(header);
        String body_hex = obj.get("body").getAsString();
        this.body = Hex.decodeHex(body_hex);

    }

    public Headers getHeader() {
        return this.header;
    }

    public String toString() {
        return new String(this.body);
    }

    public JsonElement toJson() {
        String body_str = this.toString();
        Gson gson = new Gson();
        return gson.fromJson(body_str, JsonElement.class);
    }
}
