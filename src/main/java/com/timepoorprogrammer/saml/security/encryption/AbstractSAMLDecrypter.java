package com.timepoorprogrammer.saml.security.encryption;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.xml.encryption.ChainingEncryptedKeyResolver;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;

/**
 * Abstract SAML encrypter base class.  The derived classes get the keys and setup the
 * parameters for the Encrypter here using whatever key infrastructure is expected.
 * <p/>
 * Decryption is only applicable for SAML2 and is done by a SAML2 consumer on receipt of
 * SAML payload.
 *
 * @author Jim Ball
 */
public abstract class AbstractSAMLDecrypter {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(AbstractSAMLDecrypter.class);
    /**
     * Decrypter
     */
    protected Decrypter decrypter = null;
    /**
     * Private credentials required for decryption
     */
    protected BasicCredential privateCredentials = null;

    /**
     * Decrypt an encrypted assertion.  Note this assumes the encrypted assertion contains only ONE encrypted key.
     * <p/>
     * Also, Java has an inbuilt limitation of 177 bytes or so on what can be encrypted using RSA.  So, the
     * usual mechanism is to encrypt an assertion in AES or some other symmetrical algorithm, and then
     * encrypt the key used to create the symmetrically data in RSA.  So an eavesdropper cannot read the message
     * as they cannot decrypt the encrypted key, so cannot decrypt the rest of the message symmetrically.
     * <p/>
     * This method of encrypt symmetrically (e.g. AES), then encrypt the key used asymmetrically (e.g. RSA) seems
     * to be the common transport mechanism behind SSL and most secure internet traffic.  I guess with a byte limit
     * of 177 on asymmetric encryption then assertions completely encrypted asymmetrically will have to wait till
     * the cryptographic technology is widely available.
     *
     * @param encryptedAssertion encrypted assertion
     * @return assertion
     */
    public Assertion decryptAssertion(final EncryptedAssertion encryptedAssertion) {
        if (encryptedAssertion == null || privateCredentials == null) {
            throw new IllegalArgumentException("Unable to perform decryption on assertion, missing the assertion and the decryption credentials needed");
        }
        try {
            // Get our shared session key from the encrypted assertion
            EncryptedKey key = encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0);

            // Support finding our EncryptedKey in the EncryptedAssertion in a variety of ways, as we cannot assume
            // a particular type of placement was used by the assertion producer when putting the EncryptedKey into
            // the XML.
            ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver();
            encryptedKeyResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
            encryptedKeyResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
            encryptedKeyResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());

            // Create a key resolver using our private asymmetrical encryption key pulled from our local keystore
            KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(privateCredentials);

            // Use our private key to decrypt the shared session key and get the credentials associated with
            // the decrypted shared session key.
            Decrypter decrypter = new Decrypter(null, keyResolver, encryptedKeyResolver);
            SecretKey sessionKey = (SecretKey) decrypter.decryptKey(key, encryptedAssertion.getEncryptedData().getEncryptionMethod().getAlgorithm());
            Credential sessionCredentials = SecurityHelper.getSimpleCredential(sessionKey);

            // Decrypt the assertion using our shared session key credentials
            decrypter = new Decrypter(new StaticKeyInfoCredentialResolver(sessionCredentials), null, null);
            return decrypter.decrypt(encryptedAssertion);
        } catch (Exception anyE) {
            final String errorMessage = "Error decrypting encrypted assertion";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    public Credential getPrivateKey() {
        return privateCredentials;
    }
}