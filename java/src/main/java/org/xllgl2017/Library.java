package org.xllgl2017;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

import java.io.IOException;

interface ReqrioLibrary extends Library {
    ReqrioLibrary INSTANCE = loadLibrary();

    int init_http();

    int set_header_json(int id, String header);

    int add_header(int id, String key, String value);

    int set_alpn(int id, String alpn);

    int set_proxy(int id, String proxy);

    int set_url(int id, String url);

    int add_param(int id, String name, String value);

    int set_data(int id, String data);

    int set_json(int id, String json);

    int set_content_type(int id, String context_type);

    int set_cookie(int id, String cookie);

    int add_cookie(int id, String name, String value);

    int set_timeout(int id, String timeout);

    int set_bytes(int id, byte[] bytes, int len);

    Pointer get(int id);

    Pointer post(int id);

    Pointer put(int id);

    Pointer options(int id);

    Pointer delete(int id);

    Pointer head(int id);

    Pointer trach(int id);

    void destroy(int id);

    void free_pointer(Pointer ptr);


    static ReqrioLibrary loadLibrary() {
        try {
            String tmp_dir = System.getProperty("java.io.tmpdir");
            java.io.File dll_file = new java.io.File(tmp_dir, "reqrio.dll");
            if (!dll_file.exists()) {
                try {
                    java.io.InputStream in = ReqrioLibrary.class.getResourceAsStream("/reqrio.dll");
                    java.io.OutputStream out = new java.io.FileOutputStream(dll_file);
                    byte[] buffer = new byte[4096];
                    int read;
                    while ((read = in.read(buffer)) != -1) {
                        out.write(buffer, 0, read);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                ;

            }
            return Native.load(dll_file.getAbsolutePath(), ReqrioLibrary.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}