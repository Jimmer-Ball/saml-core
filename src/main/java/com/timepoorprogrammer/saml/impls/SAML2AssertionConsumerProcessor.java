package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.core.SAMLAssertionValidationResult;
import com.timepoorprogrammer.saml.core.SAMLResponseValidationResult;
import com.timepoorprogrammer.saml.core.SAMLResponseValidationResult;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.signature.Signature;

/**
 * Default SAML2 assertion producer processor.  For a given identity provider
 * you could have one of these per target destination service provider.
 * <p/>
 * This tells the SAML2 assertion producer servlet whether or not to sign and
 * encrypt SAML it produces on the basis of dynamically changeable metadata.
 *
 * @author Jim Ball
 */
public interface SAML2AssertionConsumerProcessor {
    /**
     * Does our remote IDP sign its messages according to our metadata?
     *
     * @return true if the IDP signs messages false otherwise
     */
    public boolean idpSignsMessages();

    /**
     * Is the provided signature any good?
     *
     * @param signature signature
     * @return true if good false otherwise
     */
    public boolean isSignatureGood(final Signature signature);

    /**
     * Return the assertion decrypter to use if any.
     *
     * @return decrypter or null if its not set
     */
    public Decrypter getDecrypter();

    /**
     * Perform an auditing action on error
     *
     * @param code    error code
     * @param details provided details
     */
    public void auditError(String code, String details);

    /**
     * Perform an auditing action on success
     *
     * @param code    success code
     * @param details provided details
     */
    public void auditSuccess(String code, String details);

    /**
     * Validate the SAML 2 response contents.  For example put in place a custom single use policy here
     * by checking if the response has been received previously given its identifier, and return validation
     * results that explain precisely why the response my be invalid.  Your implementation should (like the default)
     * use the SAML2ResponseValidatorFactory to find the right validator to apply given the sender.
     *
     * @param response response
     * @return SAML response validation results
     */
    public SAMLResponseValidationResult validate(Response response);

    /**
     * Validate the SAML 2 assertion contents.  Your implementation should (like the default) use the
     * SAML2AssertionValidator factory to find the right validator to apply given the sender.
     *
     * @param assertion assertion
     * @param issuer    issuer
     * @return SAML assertion validation results
     */
    public SAMLAssertionValidationResult validate(Assertion assertion, String issuer);
}