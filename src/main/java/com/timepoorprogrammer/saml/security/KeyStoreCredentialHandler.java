package com.timepoorprogrammer.saml.security;

import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.x509.BasicX509Credential;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Handler class for private credentials that can be extracted from a local keystore for
 * either decryption when dealing with incoming SAML that needs to ve decrypted with a private
 * key or for digital signing when sending SAML out to some third party when we need to create
 * a digital signature with a private key.
 *
 * @author Jim Ball
 */
public class KeyStoreCredentialHandler {
    private KeyStore keyStore;

    /**
     * Construct with a path to the local keystore and a keystore password.
     *
     * @param keyStorePath     path
     * @param keyStorePassword password
     */
    public KeyStoreCredentialHandler(final String keyStorePath, final String keyStorePassword) {
        if (keyStorePath == null && keyStorePassword == null) {
            throw new IllegalArgumentException("Cannot create a keystore handler without a path and a password");
        }
        keyStore = KeyStoreReader.loadKeyStore(keyStorePath, keyStorePassword);
    }

    /**
     * Construct with an input stream to the local keystore and a keystore password.
     *
     * @param keyStoreStream   input stream
     * @param keyStorePassword password
     */
    public KeyStoreCredentialHandler(final InputStream keyStoreStream, final String keyStorePassword) {
        if (keyStoreStream == null || keyStorePassword == null) {
            throw new IllegalArgumentException("Cannot create a keystore handler without a stream and a password");
        }
        keyStore = KeyStoreReader.loadKeyStore(keyStoreStream, keyStorePassword);
    }

    /**
     * Get the private credentials required to decrypt a SAMLObject from the local keystore.
     *
     * @param keyAlias    alias for the key
     * @param keyPassword password for the key
     * @return private credentials required for decryption
     */
    public BasicCredential getPrivateCredentials(final String keyAlias,
                                                 final String keyPassword) {
        if (keyAlias == null || keyPassword == null) {
            throw new IllegalArgumentException("Cannot get private credentials without a keyAlias and keyPassword");
        }
        final PrivateKey privateKey = (PrivateKey) KeyStoreReader.getKey(keyStore, keyAlias, keyPassword);
        BasicCredential privateCredentials = new BasicCredential();
        privateCredentials.setPrivateKey(privateKey);
        return privateCredentials;
    }

    /**
     * Get the signing credentials required to sign a SAMLObject from the local keystore.
     *
     * @param keyAlias    alias for the key
     * @param keyPassword password for the key
     * @return signing credentials required for digital signing
     */
    public BasicX509Credential getSigningCredentials(final String keyAlias,
                                                     final String keyPassword) {
        if (keyAlias == null || keyPassword == null) {
            throw new IllegalArgumentException("Cannot get signing credentials without a keyAlias and keyPassword");
        }
        KeyStore.PrivateKeyEntry pkEntry = KeyStoreReader.getSigningDetails(keyStore, keyAlias, keyPassword);
        X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
        final BasicX509Credential signingCredentials = new BasicX509Credential();
        signingCredentials.setPrivateKey(pkEntry.getPrivateKey());
        signingCredentials.setEntityCertificate(certificate);
        return signingCredentials;
    }
}
