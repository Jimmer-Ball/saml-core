package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.core.SAMLAssertionValidationResult;
import com.timepoorprogrammer.saml.core.SAMLAssertionValidationResult;
import org.opensaml.saml2.core.Assertion;

/**
 * SAML 2 assertion validator interface.
 *
 * @author Jim Ball
 */
public interface SAML2AssertionValidator {
    /**
     * Validate the SAML 2 assertion
     *
     * @param assertion assertion
     * @param issuer issuer
     * @return validation results
     */
    SAMLAssertionValidationResult validate(Assertion assertion, String issuer);
}
