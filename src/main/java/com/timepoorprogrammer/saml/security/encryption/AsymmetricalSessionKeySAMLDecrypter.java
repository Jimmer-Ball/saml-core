package com.timepoorprogrammer.saml.security.encryption;

import com.timepoorprogrammer.saml.security.KeyStoreReader;
import com.timepoorprogrammer.saml.security.KeyStoreReader;
import org.opensaml.xml.security.credential.BasicCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyStore;
import java.security.PrivateKey;

/**
 * Decrypt shared session key on encrypted assertion using the private key pulled from local key store.
 * Then decrypt the full assertion using whatever shared symmetrical encryption mechanism was applied.
 * <p/>
 * As per the SAML2 specifications, we process EncryptedAssertions that hold a shared symmetric key
 * (session key) used to do the actual encryption of the assertion that has also been encrypted itself
 * using the recipient's (destination service provider) public key.
 * <p/>
 * So we have to unencrypt the shared symmetric key (session key) using our private asymmetric key.
 * and then once its been unencrypted use that shared symmetric key to unencrypt the assertion content.
 * <p/>
 * See page http://braindump.dk/tech/2008/05/14/opensaml-and-xml-encryption (last section) for details.
 *
 * @author Jim Ball
 */
public class AsymmetricalSessionKeySAMLDecrypter extends AbstractSAMLDecrypter {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(AsymmetricalSessionKeySAMLDecrypter.class);

    /**
     * Create an Asymmetrical Session Key decrypter for decrypting SAML content
     *
     * @param keyStorePath     path to our key store
     * @param keyStorePassword password for our keystore
     * @param keyPassword      password for our private key
     * @param keyAlias         key alias in our key store for our private key
     */
    public AsymmetricalSessionKeySAMLDecrypter(final String keyStorePath,
                                               final String keyStorePassword,
                                               final String keyPassword,
                                               final String keyAlias) {

        if (keyStorePath == null || keyStorePassword == null || keyPassword == null || keyAlias == null) {
            throw new IllegalArgumentException("Missing arguments, unable to establish private key credentials required for decryption");
        }
        try {
            // Obtain the private key credentials from our keystore
            final KeyStore keyStore = KeyStoreReader.loadKeyStore(keyStorePath, keyStorePassword);
            final PrivateKey privateKey = (PrivateKey) KeyStoreReader.getKey(keyStore, keyAlias, keyPassword);
            privateCredentials = new BasicCredential();
            privateCredentials.setPrivateKey(privateKey);
        } catch (Exception anyE) {
            final String errorMessage = "Error creating decryption baseline";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }
}