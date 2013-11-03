package com.timepoorprogrammer.saml.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Simple utility for reading JKS KeyStores.
 *
 * @author Jim Ball
 */
public class KeyStoreReader {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(KeyStoreReader.class);
    /**
     * End of line property
     */
    private static final String END_OF_LINE = System.getProperty("line.separator");


    /**
     * Load a KeyStore object given the keystore filepath (as a string) and the keystore password.
     *
     * @param filepath filename
     * @param password store password
     * @return keystore object
     */
    public static KeyStore loadKeyStore(String filepath, String password) {
        if (filepath == null || password == null) {
            throw new IllegalArgumentException("Cannot load key store without a filepath and a password");
        }
        KeyStore result;
        try {
            result = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream in = new FileInputStream(filepath);
            result.load(in, password.toCharArray());
            in.close();
        } catch (Exception anyE) {
            final String errorMessage = "Error loading security keystore details";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
        return result;
    }

    /**
     * Load a KeyStore object given the keystore filepath (as a stream) and keystore password.
     *
     * @param in       input stream
     * @param password store password
     * @return keystore
     */
    public static KeyStore loadKeyStore(InputStream in, String password) {
        if (in == null || password == null) {
            throw new IllegalArgumentException("Cannot load key store without a stream and a password");
        }
        KeyStore result;
        try {
            result = KeyStore.getInstance(KeyStore.getDefaultType());
            result.load(in, password.toCharArray());
        } catch (Exception anyE) {
            final String errorMessage = "Error loading security keystore details";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
        return result;
    }

    /**
     * List all the key and certificate aliases in the keystore.
     *
     * @param keystore loaded keystore
     * @return list of aliases
     */
    public static List<String> getAliases(KeyStore keystore) {
        if (keystore == null) {
            throw new IllegalArgumentException("Cannot get aliases in a keystore without a keystore");
        }
        try {
            return Collections.list(keystore.aliases());
        } catch (Exception anyE) {
            final String errorMessage = "Error getting key and certificate alias listing";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Get a key from the keystore by alias and by key password.
     *
     * @param keystore loaded keystore
     * @param alias    alias for key
     * @param password key password
     * @return key
     */
    public static Key getKey(KeyStore keystore, String alias, String password) {
        if (keystore == null || alias == null || password == null) {
            throw new IllegalArgumentException("Cannot get key from keystore without a keystore, an alias, and a password");
        }
        try {
            return keystore.getKey(alias, password.toCharArray());
        } catch (Exception anyE) {
            final String errorMessage = "Error getting key details given keystore, key alias and key password";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Get the details needed to digitally sign something. Most often used when sending something out on the
     * wire we need to sign, so the receiving end can check if its been tampered with in-transit.
     *
     * @param keyStore keystore
     * @param alias    key alias
     * @param password key password
     * @return PrivateKeyEntry
     */
    public static PrivateKeyEntry getSigningDetails(KeyStore keyStore, String alias, String password) {
        if (keyStore == null || alias == null || password == null) {
            throw new IllegalArgumentException("Cannot get signing details without a keystore, and alias, and a password");
        }
        try {
            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
                    new KeyStore.PasswordProtection(password.toCharArray()));
        } catch (Exception anyE) {
            final String errorMessage = "Error obtaining PrivateKeyEntry for digitial signature";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Get a certificate from the keystore by alias.
     * Most often used when validating a signature on incoming data.
     *
     * @param keystore keystore
     * @param alias    alias
     * @return certificate
     */
    public static Certificate getCertificate(KeyStore keystore, String alias) {
        if (keystore == null || alias == null) {
            throw new IllegalArgumentException("Cannot get a certificate without a keystore and an alias");
        }
        try {
            return keystore.getCertificate(alias);
        } catch (Exception anyE) {
            final String errorMessage = "Error getting certificate details given keystore and certificate alias";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Show details held in a private key
     *
     * @param key key
     * @return readable key details
     */
    public static String showDetails(Key key) {
        if (key == null) {
            throw new IllegalArgumentException("Private key not provided, we cannot show its details");
        }
        StringBuffer buffer = new StringBuffer
                ("Algorithm: " + key.getAlgorithm() + END_OF_LINE +
                        "Key value: " + END_OF_LINE);
        appendHexValue(buffer, key.getEncoded());
        return buffer.toString();
    }

    /**
     * Show details held in a certificate.
     *
     * @param cert certificate
     * @return certifcate contents
     */
    public static String showDetails(Certificate cert) {
        if (cert == null) {
            throw new IllegalArgumentException("Certificate not provided, we cannot show its details");
        }
        try {
            StringBuffer buffer = new StringBuffer
                    ("Certificate type: " + cert.getType() + END_OF_LINE +
                            "Encoded data: " + END_OF_LINE);
            appendHexValue(buffer, cert.getEncoded());
            return buffer.toString();
        } catch (Exception anyE) {
            final String errorMessage = "Error printing certificate details";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Helper method that converts a single byte to a hex string representation.
     *
     * @param buffer with the two-digit hex string
     * @param b      byte Byte to convert
     */
    private static void appendHexValue(StringBuffer buffer, byte b) {
        int[] digits = {(b >>> 4) & 0x0F, b & 0x0F};
        for (int digit : digits) {
            int increment = (int) ((digit < 10) ? '0' : ('a' - 10));
            buffer.append((char) (digit + increment));
        }
    }

    /**
     * Helper that appends a hex representation of a byte array to an
     * existing StringBuffer.
     *
     * @param buffer buffer
     * @param bytes  hex representation
     */
    private static void appendHexValue(StringBuffer buffer, byte[] bytes) {
        for (byte aByte : bytes) appendHexValue(buffer, aByte);
    }
}

