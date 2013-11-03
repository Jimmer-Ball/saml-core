package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.core.SAMLAssertionValidationResult;
import org.opensaml.saml1.core.Assertion;

/**
 * SAML 1.1 assertion validator interface.
 *
 * @author Jim Ball
 */
public interface SAML11AssertionValidator {
    /**
     * Validate the SAML 1.1 assertion
     *
     * @param assertion assertion
     * @param issuer issuer
     * @return validation results
     */
    SAMLAssertionValidationResult validate(Assertion assertion, String issuer);
}
