package com.timepoorprogrammer.saml.core;

import org.apache.commons.lang.StringUtils;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.Response;

/**
 * Inbound SAML1.1 message details as would be presented at an assertion consumer service for SAML 1.1
 *
 * @author Jim Ball
 */
public class InboundSAML11Message {
    Response response;
    String relayState;
    String issuer;
    Assertion assertion;

    /**
     * Get the SAML1.1 payload contents from the inbound message context, so the SAML response, the relay state, and the
     * issuer details
     *
     * @param context SAML inbound message context
     */
    public InboundSAML11Message(final SAMLMessageContext context) {
        if (context == null) {
            throw new IllegalArgumentException("Cannot get SAML1.1 contents without a message context");
        }
        response = (Response) context.getInboundMessage();
        relayState = context.getRelayState();
        assertion = response.getAssertions().get(0);
        if (assertion != null) {
            issuer = assertion.getIssuer();
        }
    }

    /**
     * A consumer cannot manage incoming SAML1.1 unless it has the basics needed to determine how to process the
     * message.  At a minimum these are the SAML response, the assertion itself, and the issuer details.  The relayState is
     * not mandatory.
     * <p/>
     * Note we can get at the assertion straight off in SAML 1.1 as the SAML 1.1 specification doesn't allow for
     * encryption of assertions by clients of remote services, it just isn't as secure as SAML2, hence the existance
     * of the newer standard.
     *
     * @return true if the incoming message is manageable, false otherwise
     */
    public boolean hasRequiredDetails() {
        return response != null && assertion != null && issuer != null;
    }

    /**
     * Get the SAML "response" encapsulation within which our assertion will hide, as extracted from the payload.
     * <p/>
     * When POSTing a SAML1.1 assertion to some other consumer, this needs to be the held as the value of the
     * parameter named "SAMLResponse".
     *
     * @return SAML response body
     */
    public Response getResponse() {
        return response;
    }

    /**
     * Within SAML1.1 the relay state can be used to hold guiding information to a remote service to say which
     * module (for example) should be accessed within the service.  This is completely free-form and is effectively
     * an out-of-bounds agreement between a service and the outside world.  There has been some debate as to whether
     * the attributes of an assertion should be used to hold this sort of information.  But, the general consensus
     * is the attributes should be used to hold modification details to the asserted identity (like say the user's
     * role) and not service level information.  It is common for services to expect a client to use the relayState
     * to identify a "deep-dive" part of the target service that the target service understands.  So, for MyView
     * for example this is where we'd put the myView "module" name to allow the target service MyView to single-sign-on
     * deep-dive.
     * <p/>
     * When POSTING a SAML1.1 assertion to some other consumer, this may be provided as the vale of the parameter
     * named "TARGET" within the POST body.  I say may as if you don't have a specific bit of information like
     * module name to pass on to the remote service, then you should not provide the parameter at all.
     * <p/>
     * Note the name of the parameter in the POST body used in SAML1.1 is different than the name of the parameter
     * used in SAML2
     *
     * @return contextual information the target service understands (like say the module to deep-dive to) or null
     *         if its not been provided (as it doesn't HAVE to be) or is empty
     */
    public String getRelayState() {
        return StringUtils.isEmpty(relayState) ? null : relayState;
    }

    /**
     * In order to process an incoming assertion the assertion consumer has ot know who it came from so it can look up
     * the appropriate SAML meta-data information for the issuer to know how to process the payload as agreed in the
     * meta-data contract.
     *
     * @return issuer (who the assertion came from)
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * In SAML1.1, assertions are not encrypted as the SAML1.1 standard doesn't allow for it, so we can reach in a
     * grab the assertion from the context straight off.
     *
     * @return assertion
     */
    public Assertion getAssertion() {
        return assertion;
    }
}
