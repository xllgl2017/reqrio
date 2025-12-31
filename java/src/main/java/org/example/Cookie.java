package org.example;

public class Cookie {
    private String name;
    private String value;
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
}
