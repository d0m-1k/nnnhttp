package pro.nnnteam.httplib;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class HTTPResult {
    private byte[] data = null;
    private int resultCode = 200;
    private String contentType = "text/html";
    private HashMap<String, String> headers = new HashMap<>();

    // Геттеры
    public byte[] getData() { return data; }
    public int getResultCode() { return resultCode; }
    public String getContentType() { return contentType; }
    public Map<String, String> getHeaders() { return Collections.unmodifiableMap(headers); }

    public static class Builder {
        private HTTPResult httpResult = new HTTPResult();

        public Builder data(byte[] data) { httpResult.data = data; return this; }
        public Builder data(Object data) { httpResult.data = data.toString().getBytes(); return this; }
        public Builder resultCode(int resultCode) { httpResult.resultCode = resultCode; return this; }
        public Builder contentType(String contentType) { httpResult.contentType = contentType; return this; }
        public Builder putHeader(String key, String value) {
            if (httpResult.headers == null) httpResult.headers = new HashMap<>();
            httpResult.headers.put(key, value);
            return this;
        }
        public HTTPResult build() { return httpResult; }
    }
}
