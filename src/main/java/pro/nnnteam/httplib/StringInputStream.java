package pro.nnnteam.httplib;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class StringInputStream extends InputStream {
    private final byte[] bytes;
    private int index;

    public StringInputStream(String data) {
        this(data, StandardCharsets.UTF_8);
    }

    public StringInputStream(String data, Charset charset) {
        this.bytes = data.getBytes(charset);
        this.index = 0;
    }

    @Override
    public int available() {
        return bytes.length - index;
    }

    @Override
    public int read() {
        if (index >= bytes.length) return -1;
        return bytes[index++] & 0xFF;
    }

    @Override
    public String toString() {
        return new String(bytes, StandardCharsets.UTF_8);
    }
}