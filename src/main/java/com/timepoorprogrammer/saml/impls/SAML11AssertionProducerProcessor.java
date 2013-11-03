package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.core.SAML11Handler;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.Response;
import org.opensaml.xml.signature.Signature;

import java.util.Map;

/**
 * Default SAML assertion producer processor.  For an identity provider
 * you could have one of these per target destination service provider endpoint.
 * <p/>
 * The tells the assertion producer servlet whether or not to sign SAML it produces
 * on the basis of dynamically changeable metadata.
 *
 * @author Jim Ball
 */
public interface SAML11AssertionProducerProcessor {

    /**
     * Get the target destination URL as defined in metadata against the AssertionConsumerService
     * on the remote service provider that meets the protocol this identity provider is using.
     * <p/>
     * This value is key.  If the assertion arrives at the target destination assertion consumer
     * service and the then locally derived URL for the assertion consumer does not resolve to this value
     * then the assertion consumer service will reject the assertion out of hand.  This is what
     * the specification intends, and what OpenSAML does for us behind the scenes.  So setting this
     * URL in the metadata means understanding that the public address of an assertion consumer can
     * be matched locally by the assertion consumer itself on reception of an assertion.  This usually
     * means a dialogue with hosting to confirm what the assertion consumer URL should be BEFORE sending
     * any service provider metadata out to a customer, and often means two copies of meta-data, one holding
     * public addresses used by the outside world to access our services, and one used by hosting to
     * identify the URL for service access points after they've been transformed to "local addresses" by the
     * proxy on the edge of hosting.
     *
     * @return destination
     */
    public String getDestination();

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
     * Create a SAML1.1 response
     *
     * @param samlHandler SAML1.1 handler
     * @return SAML2 response
     */
    public Response createResponse(SAML11Handler samlHandler);

    /**
     * Create a SAML1.1 authentication assertion
     *
     * @param samlHandler    SAML2 handler
     * @param userIdentifier user identifier for the payload
     * @return SAML1.1 authentication assertion
     */
    public Assertion createAuthnAssertion(SAML11Handler samlHandler, String userIdentifier);

    /**
     * Create a SAML1 authentication assertion with extra attributes
     *
     * @param samlHandler    SAML2 handler
     * @param userIdentifier user identifier for the payload
     * @param attributes     attributes to add to the assertion
     * @return SAML2 authentication assertion
     */
    public Assertion createAuthnAssertion(SAML11Handler samlHandler, String userIdentifier,
                                          Map<String, String> attributes);

    /**
     * Finish the blank signature provided.
     *
     * @param blankSignature blank signature
     */
    public void finishSignature(Signature blankSignature);
}