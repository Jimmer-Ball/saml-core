package com.timepoorprogrammer.saml.impls.standard.producer.processor;

import com.timepoorprogrammer.saml.core.SAML11Handler;
import com.timepoorprogrammer.saml.impls.MetaDataHandler;
import com.timepoorprogrammer.saml.impls.SAML11AssertionProducerProcessor;
import com.timepoorprogrammer.saml.security.signature.X509SAMLSignatureCreator;
import com.timepoorprogrammer.saml.security.signature.X509SAMLSignatureCreator;
import org.opensaml.saml1.core.*;
import org.opensaml.saml2.metadata.provider.MetadataProvider;

import java.util.Map;

/**
 * Default SAML 1.1 assertion producer processor.
 *
 * @author Jim Ball
 */
public class SAML11AssertionProducerProcessorImpl extends SAMLAssertionProducerProcessorBase
        implements SAML11AssertionProducerProcessor {

    /**
     * Time window parameters within which the assertion consumer service at the remote
     * service provider should begin to accept the assertion.  So this defines the temporal
     * validity window it should take an assertion we make to reach the other end.
     */
    private int TIME_BEFORE_IN_SECONDS = 30;
    private int TIME_AFTER_IN_MINUTES = 30;

    /**
     * Construct a SAML1.1 assertion producer processor passing the following arguments at minimum:-
     * <ul>
     * <li>The filepath for our metadata</li>
     * <li>The identity provider's unique id which matches up with metadata</li>
     * <li>The SAML protocol (either 2.0 or 1.1) our identity provider uses to create SAML messages, so either
     * SAMLConstant.SAML11P_NS == urn:oasis:names:tc:SAML:1.1:protocol, or SAMLConstants.SAML20P_NS ==
     * urn:oasis:names:tc:SAML:2.0:protocol</li>
     * <li>The service provider's unique id which matches up with metadata</li>
     * <li>The metadata handler</li>
     * </ul>
     * <p/>
     * The rest of the arguments describe any signing architecture we might apply to outgoing SAML messages
     * and can (in development) be null, but must be not null in a production system to meet the SAML specs.
     * <p/>
     * Note: This is called from a factory because there may be many implementations of these depending on the
     * remote service provider we are sending to, their metadata, and any "special" features they may want.
     *
     * @param metaDataFilePath            metadata file path
     * @param idpId                       identity provider SAML entity identifier
     * @param idpProtocol                 identity provider SAML protocol to use
     * @param serviceCode                 service provider internal Northgate code
     * @param spId                        service provider SAML entity identifier
     * @param mdHandler                   metadata handler
     * @param signingKeyStoreFilePath     The file path for the keystore holding the private key we as a identity
     *                                    provider would use to sign an outbound SAML message or null.
     * @param signingKeyStoreFilePassword The password for the keystore holding the signing key or null.
     * @param signingKeyAlias             The alias of the signing key in the keystore or null;
     * @param signingKeyPassword          The password for the signing key or null.
     */
    public SAML11AssertionProducerProcessorImpl(final String metaDataFilePath,
                                                final String idpId,
                                                final String idpProtocol,
                                                final String serviceCode,
                                                final String spId,
                                                final MetaDataHandler mdHandler,
                                                final String signingKeyStoreFilePath,
                                                final String signingKeyStoreFilePassword,
                                                final String signingKeyAlias,
                                                final String signingKeyPassword) {
        super(metaDataFilePath, idpId, idpProtocol, serviceCode, spId, mdHandler, signingKeyStoreFilePath,
                signingKeyStoreFilePassword, signingKeyAlias, signingKeyPassword);
    }

    public SAML11AssertionProducerProcessorImpl(final MetadataProvider mdProvider,
                                                final String idpId,
                                                final String idpProtocol,
                                                final String serviceCode,
                                                final String spId,
                                                final MetaDataHandler mdHandler,
                                                final X509SAMLSignatureCreator sigCreator,
                                                final String signingKeyAlias,
                                                final String signingKeyPassword) {
        super(mdProvider, idpId, idpProtocol, serviceCode, spId, mdHandler, sigCreator, signingKeyAlias, signingKeyPassword);
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML11AssertionProducerProcessor#auditError(String, String)
     */
    public void auditError(String code, String details) {
        auditMessenger.auditError(code, idpId, idpProtocol, spId, details);
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML11AssertionProducerProcessor#auditSuccess(String, String)
     */
    public void auditSuccess(String code, String details) {
        auditMessenger.auditSuccess(code, idpId, idpProtocol, spId, details);
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML11AssertionProducerProcessor#createResponse(com.timepoorprogrammer.saml.core.SAML11Handler)
     */
    public Response createResponse(SAML11Handler samlHandler) {
        // Create a SAML1.1 response indicating success, who its from (the issuer details provided on
        // SAMLHandler construction), and set the destination to the remote SAML consumer service as
        // set in the destination service provider metadata.
        //
        // Note: The remote service provider will read metadata using the provider issuer name as a key
        // to lookup the identity provider configuration so it can validate the SAML response and assertion
        // it receives.
        //
        // Note: With SAML1.1 there is no issuer element in the SAML response body, only one in the assertion
        Response samlResponse = samlHandler.createResponse(StatusCode.SUCCESS, "AccessRequest", null);
        samlResponse.setRecipient(this.getDestination());
        return samlResponse;
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML11AssertionProducerProcessor#createAuthnAssertion(com.timepoorprogrammer.saml.core.SAML11Handler, String)
     */
    public Assertion createAuthnAssertion(SAML11Handler samlHandler, String userIdentifier) {
        // Create a subject with user identifier, source domain, unspecified NameIdentifer type, from bearer
        final Subject subject = samlHandler.createSubject(userIdentifier, idpId, NameIdentifier.UNSPECIFIED, "bearer");
        // Create assertion with subject, password context, and time before (seconds), and time to live (minutes)
        return samlHandler.createAssertion(subject, TIME_BEFORE_IN_SECONDS, TIME_AFTER_IN_MINUTES);
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML11AssertionProducerProcessor#createAuthnAssertion(com.timepoorprogrammer.saml.core.SAML11Handler, String, java.util.Map)
     */
    @Override
    public Assertion createAuthnAssertion(SAML11Handler samlHandler, String userIdentifier, Map<String, String> attributes) {
        // Create a subject with user identifier, source domain, unspecified NameIdentifer type, from bearer
        final Subject subject = samlHandler.createSubject(userIdentifier, idpId, NameIdentifier.UNSPECIFIED, "bearer");
        // Create assertion with subject, password context, and time before (seconds), and time to live (minutes)
        return samlHandler.createAssertion(subject, TIME_BEFORE_IN_SECONDS, TIME_AFTER_IN_MINUTES, attributes);
    }
}