package org.xllgl2017;

public enum ALPN {
    HTTP10("http/1.0"),
    HTTP11("http/1.1"),
    HTTP20("h2");

    private final String value;

    ALPN(String value) {
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }
}
