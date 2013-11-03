package com.timepoorprogrammer.saml.security.encryption;

import com.timepoorprogrammer.saml.security.KeyStoreReader;
import com.timepoorprogrammer.saml.security.KeyStoreReader;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;

/**
 * Encrypt SAMLObject using shared symmetric session key.  Then encrypt shared session key using public key
 * pulled from metadata.
 * <p/>
 * As per the SAML2 specifications, this uses a symmetric key (session key) to do the actual encryption
 * but uses the recipient's (destination service provider) public key pulled from the imported
 * certificate (from metadata) they gave us to asymmetrically encrypt the session key.  This is the
 * standard PKI approach to asymmetrical encryption of large XML payloads, basically you don't
 * go the whole way of encrypting the complete assertion asymmetrically (as it will fail at 177 bytes-ish),
 * just the session key that allows you to decrypt the content symmetrically.
 * <p/>
 * So the recipient would decrypt the session key with their private asymmetrical key and then use
 * the unencrypted session key to decrypt the assertion.
 * <p/>
 * See page http://braindump.dk/tech/2008/05/14/opensaml-and-xml-encryption/ last section for details.
 *
 * @author Jim Ball
 */
public class AsymmetricalSessionKeySAMLEncrypter extends AbstractSAMLEncrypter {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(AsymmetricalSessionKeySAMLEncrypter.class);

    /**
     * Create an Asymmetrical Session Key encrypter for encrypting SAML content using the public credentials
     * that we passed in through the constructor.  Chances are these were picked up from the metadata the
     * system was started with.
     *
     * @param encryptionCredentials extracted from SAML metadata
     * @param algorithm             to apply from SAML metadata
     */
    public AsymmetricalSessionKeySAMLEncrypter(final Credential encryptionCredentials, final String algorithm) {
        if (encryptionCredentials == null || algorithm == null) {
            throw new IllegalArgumentException("Missing encryption credentials and algorithm details required for encryption");
        }
        try {
            // Create an AES128 shared session key key we'll place in the outgoing encrypted assertion
            final SecretKey sessionKey = SecurityHelper.generateSymmetricKey(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
            Credential symmetricCredential = SecurityHelper.getSimpleCredential(sessionKey);
            EncryptionParameters encParams = new EncryptionParameters();
            encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
            encParams.setEncryptionCredential(symmetricCredential);

            // Setup so we encrypt the shared session key using the destination/recipient's credentials
            // and have it ready to go in the EncryptedAssertion.
            KeyEncryptionParameters kek = new KeyEncryptionParameters();
            kek.setEncryptionCredential(encryptionCredentials);
            kek.setAlgorithm(algorithm);

            // Setup the encrypter and make sure we put our shared key in there too inline
            encrypter = new Encrypter(encParams, kek);
            encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);
        } catch (Exception anyE) {
            final String errorMessage = "Error creating encryption baseline";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Create an Asymmetrical Session Key encrypter for encrypting SAML content where we get the public key
     * content from a local keystore rather than metadata.
     *
     * @param keyStorePath     path to our key store
     * @param keyStorePassword password for our keystore
     * @param keyAlias         key alias in our key store for the public key of the recipient/destination service
     *                         provider
     */
    public AsymmetricalSessionKeySAMLEncrypter(final String keyStorePath,
                                               final String keyStorePassword,
                                               final String keyAlias) {
        try {
            if (keyStorePath != null && keyStorePassword != null && keyAlias != null) {
                // Create an AES128 shared session key key we'll place in the outgoing encrypted assertion
                final SecretKey sessionKey = SecurityHelper.generateSymmetricKey(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
                Credential symmetricCredential = SecurityHelper.getSimpleCredential(sessionKey);
                EncryptionParameters encParams = new EncryptionParameters();
                encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
                encParams.setEncryptionCredential(symmetricCredential);

                // Setup the destination/recipient's public key credentials from our keystore's service certificate
                final KeyStore keyStore = KeyStoreReader.loadKeyStore(keyStorePath, keyStorePassword);
                final Certificate serviceCertificate = KeyStoreReader.getCertificate(keyStore, keyAlias);
                final PublicKey publicKey = serviceCertificate.getPublicKey();
                final BasicCredential publicCredentials = new BasicCredential();
                publicCredentials.setPublicKey(publicKey);

                // Setup so we encrypt the shared session key using the destination/recipient's public key from our keystore
                // and have it ready to go in the EncryptedAssertion.
                KeyEncryptionParameters kek = new KeyEncryptionParameters();
                kek.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15);
                kek.setEncryptionCredential(publicCredentials);

                // Setup the encrypter and make sure we put our shared key in there too
                encrypter = new Encrypter(encParams, kek);
                encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);
            } else {
                final String errorMessage = "Missing arguments, unable to establish public key credentials";
                log.error(errorMessage);
                throw new RuntimeException(errorMessage);
            }
        } catch (Exception anyE) {
            final String errorMessage = "Error creating encryption baseline";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }
}
