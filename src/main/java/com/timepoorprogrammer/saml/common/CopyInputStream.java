package com.timepoorprogrammer.saml.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * It is a well known pain but if you are dealing with base Input streams in Java, once you've
 * read them the once then the pointer in the stream is at the end of the stream.  Now you might
 * have no idea how to rewind it, it may be from an URL, it may be from a File, it may be from
 * wherever, but you definitely may want to "just" re-read it.  In which case you need to take
 * a copy of the original stream each time you re-read.
 * <p/>
 * See this in action with the SAML2AssertionConsumer class, as each time we get a processor we
 * need to re-read the local key store to get hold of the private key used in decryption and this
 * depends on the service being called.
 *
 * @author Jim Ball
 */
public class CopyInputStream {
    private InputStream _is;
    private ByteArrayOutputStream _copy = new ByteArrayOutputStream();

    /**
     * Copy the input stream
     *
     * @param is input stream
     */
    public CopyInputStream(InputStream is) {
        if (is == null) {
            throw new IllegalArgumentException("Input stream cannot be null");
        }
        _is = is;
        try {
            copy();
        } catch (IOException ex) {
            throw new RuntimeException("Error copying the input stream", ex);
        }
    }

    /**
     * Copy the input stream to allow re-reading without hitting an end of stream fiasco.
     *
     * @return copy of the input stream
     * @throws IOException on error
     */
    private int copy() throws IOException {
        int read = 0;
        int chunk;
        byte[] data = new byte[256];
        while (-1 != (chunk = _is.read(data))) {
            read += data.length;
            _copy.write(data, 0, chunk);
        }
        return read;
    }

    /**
     * Get a copy of the input stream we were constructed with.
     *
     * @return copy of input stream
     */
    public InputStream getCopy() {
        return new ByteArrayInputStream(_copy.toByteArray());
    }
}