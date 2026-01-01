package org.xllgl2017;

public class Cookie {
    private final String name;
    private final String value;
    private int age;
    private String domain;
    private String path;
    private boolean http_only;
    private boolean secure;
    private String expires;
    private String same_site;
    private boolean icpsp;

    public Cookie(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public String getName() {
        return name;
    }
}
