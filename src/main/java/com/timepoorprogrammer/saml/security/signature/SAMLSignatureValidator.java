package com.timepoorprogrammer.saml.security.signature;

import com.timepoorprogrammer.saml.security.KeyStoreReader;
import com.timepoorprogrammer.saml.security.KeyStoreReader;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;

/**
 * SAML signature validator.  If coming from metadata, we can use a more advanced technique
 * that uses trust engines.
 *
 * @author Jim Ball
 */
public class SAMLSignatureValidator {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(SAMLSignatureValidator.class);
    /**
     * Signature to apply
     */
    private SignatureValidator sigValidator = null;

    /**
     * Create a signature with which we can sign SAML objects
     *
     * @param keyStorePath     path to key store
     * @param keyStorePassword password for key store
     * @param keyPassword      producer private key password
     * @param keyAlias         producer private key alias
     */
    public SAMLSignatureValidator(final String keyStorePath,
                                  final String keyStorePassword,
                                  final String keyPassword,
                                  final String keyAlias) {
        if (keyStorePath == null || keyStorePassword == null || keyPassword == null || keyAlias == null) {
            throw new IllegalArgumentException("Missing arguments, unable to create signature");
        }
        // Create the credentials required to validate a signature
        final KeyStore keyStore = KeyStoreReader.loadKeyStore(keyStorePath, keyStorePassword);
        final Certificate clientCertificate = KeyStoreReader.getCertificate(keyStore, keyAlias);
        final PublicKey publicKey = clientCertificate.getPublicKey();
        BasicX509Credential credential = new BasicX509Credential();
        credential.setPublicKey(publicKey);
        // Create a signature validator on the basis of the credentials
        sigValidator = new SignatureValidator(credential);
    }

    /**
     * Is the signed response valid?
     *
     * @param response response
     * @return true if signature is valid false otherwise
     */
    public boolean isValid(final Response response) {
        boolean isValid = true;
        Signature signature = response.getSignature();
        if (signature != null) {
            try {
                sigValidator.validate(signature);
            } catch (ValidationException ve) {
                log.info("Signature is invalid, access denied");
                isValid = false;
            }
            return isValid;
        } else {
            final String errorMessage = "Resource is not signed";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * Is the signed assertion valid?
     *
     * @param assertion assertion
     * @return true if signature is valid false otherwise
     */
    public boolean isValid(final Assertion assertion) {
        boolean isValid = true;
        Signature signature = assertion.getSignature();
        if (signature != null) {
            try {
                sigValidator.validate(signature);
            } catch (ValidationException ve) {
                log.info("Signature is invalid, access denied");
                isValid = false;
            }
            return isValid;
        } else {
            final String errorMessage = "Resource is not signed";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }
}