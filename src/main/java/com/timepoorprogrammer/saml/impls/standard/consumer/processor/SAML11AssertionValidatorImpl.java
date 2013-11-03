package com.timepoorprogrammer.saml.impls.standard.consumer.processor;

import com.timepoorprogrammer.saml.common.AuditMessages;
import com.timepoorprogrammer.saml.core.SAMLAssertionValidationResult;
import com.timepoorprogrammer.saml.impls.SAML11AssertionValidator;
import com.timepoorprogrammer.saml.common.AuditMessages;
import org.joda.time.DateTime;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.AuthenticationStatement;

import java.util.Date;

/**
 * Standard SAML11 assertion validator
 *
 * @author Jim Ball
 */
public class SAML11AssertionValidatorImpl implements SAML11AssertionValidator {
    /**
     * If you want to override this behaviour, I suggest you derive off this class and call this method anyway, as the
     * set of tests here really are the "minimal" set of tests that should be applied to an inbound SAML1.1 assertion.
     * Anything else you want to do should be an extension of this base set of tests.
     *
     * @param assertion assertion assertion
     * @param issuer    issuer expected issuer
     * @return validation result
     */
    @Override
    public SAMLAssertionValidationResult validate(Assertion assertion, String issuer) {
        SAMLAssertionValidationResult result = new SAMLAssertionValidationResult();
        try {
            if (assertion.getMajorVersion() == 1 && assertion.getMajorVersion() == 1) {
                if (assertion.getIssuer() != null && assertion.getIssuer().equals(issuer)) {
                    if (assertion.getConditions() != null && assertion.getConditions().getNotBefore() != null && assertion.getConditions().getNotOnOrAfter() != null) {
                        final DateTime notBefore = assertion.getConditions().getNotBefore();
                        final DateTime notOnOrAfter = assertion.getConditions().getNotOnOrAfter();
                        Date now = new Date();
                        if (notBefore.toDate().before(now) && notOnOrAfter.toDate().after(now)) {
                            final AuthenticationStatement authStatement = assertion.getAuthenticationStatements().get(0);
                            if (authStatement != null && authStatement.getSubject() != null
                                    && authStatement.getSubject().getNameIdentifier().getNameIdentifier() != null) {
                                result.setValid(true);
                            } else {
                                // The assertion is missing subject details, so we don't know for whoom it applies
                                result.setErrorDetails(AuditMessages.ConsumerCode.CONSUMER_ASSERTION_MISSING_SUBJECT_ERROR.getDetailsPattern());
                                result.setValid(false);
                            }
                        } else {
                            // The assertion is either too old or too young for us to process
                            result.setErrorDetails(AuditMessages.ConsumerCode.CONSUMER_ASSERTION_INVALID_TIMEFRAME_ERROR.getDetailsPattern());
                            result.setValid(false);
                        }
                    } else {
                        // Missing temporal conditions on the assertion, so the assertion's validity window, so we cannot
                        // establish if the assertion is too old or too early for us to process.
                        result.setErrorDetails(AuditMessages.ConsumerCode.CONSUMER_ASSERTION_MISSING_TIMEFRAME_ERROR.getDetailsPattern());
                        result.setValid(false);
                    }
                } else {
                    // Missing issuer details or issuer details in assertion don't match the expected issuer
                    result.setErrorDetails(AuditMessages.ConsumerCode.CONSUMER_ASSERTION_ISSUER_ERROR.getDetailsPattern());
                    result.setValid(false);
                }
            } else {
                // Invalid SAML assertion version provided, we only process SAML 1.1 or SAML2
                result.setErrorDetails(AuditMessages.ConsumerCode.CONSUMER_ASSERTION_VERSION_ERROR.getDetailsPattern()
                        + ": " + assertion.getMajorVersion() + "." + assertion.getMinorVersion());
                result.setValid(false);
            }
        } catch (Exception anyE) {
            result.setErrorDetails("Unexpected error validating SAML1.1 assertion: " + anyE.getMessage());
            result.setValid(false);
        }
        return result;
    }
}
