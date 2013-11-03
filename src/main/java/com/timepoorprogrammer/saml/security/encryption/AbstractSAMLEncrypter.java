package com.timepoorprogrammer.saml.security.encryption;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.encryption.Encrypter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract SAML encrypter base class.  The derived classes get the keys and setup the
 * parameters for the Encrypter here using whatever key infrastructure is expected.
 *
 * @author Jim Ball
 */
public abstract class AbstractSAMLEncrypter {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(AbstractSAMLEncrypter.class);
    /**
     * OpenSAML encrypter that is setup by a derived class
     */
    protected Encrypter encrypter = null;

    /**
     * Encrypt an assertion
     *
     * @param assertion assertion
     * @return encrypted assertion
     */
    public EncryptedAssertion encryptAssertion(final Assertion assertion) {
        if (assertion == null || encrypter == null) {
            throw new IllegalArgumentException("Unable to perform encryption on assertion, missing the assertion and encrypter required");
        }
        try {
            return encrypter.encrypt(assertion);
        } catch (Exception anyE) {
            final String errorMessage = "Error encrypting assertion";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }
}
