package com.timepoorprogrammer.saml.impls.standard.producer.processor;

import com.timepoorprogrammer.saml.core.SAML2Handler;
import com.timepoorprogrammer.saml.impls.MetaDataHandler;
import com.timepoorprogrammer.saml.impls.SAML2AssertionProducerProcessor;
import com.timepoorprogrammer.saml.security.encryption.AsymmetricalSessionKeySAMLEncrypter;
import com.timepoorprogrammer.saml.security.signature.X509SAMLSignatureCreator;
import com.timepoorprogrammer.saml.core.SAML2Handler;
import com.timepoorprogrammer.saml.impls.MetaDataHandler;
import com.timepoorprogrammer.saml.impls.SAML2AssertionProducerProcessor;
import com.timepoorprogrammer.saml.security.signature.X509SAMLSignatureCreator;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.xml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Default SAML2 assertion producer processor.
 *
 * @author Jim Ball
 */
public class SAML2AssertionProducerProcessorImpl extends SAMLAssertionProducerProcessorBase implements SAML2AssertionProducerProcessor {
    private static final Logger log = LoggerFactory.getLogger(SAML2AssertionProducerProcessorImpl.class);

    /**
     * Time window parameters within which the assertion consumer service at the remote
     * service provider should begin to accept the assertion.  So this defines how long
     * we've got to make sure any assertion reaches the consumer at the other end.
     */
    public int TIME_BEFORE_IN_SECONDS = 30;
    public int TIME_AFTER_IN_MINUTES = 30;

    /**
     * Construct a SAML2 assertion producer processor
     *
     * @param metaDataFilePath            metadata file path
     * @param idpId                       identity provider SAML entity identifier
     * @param idpProtocol                 identity provider SAML protocol to use
     * @param serviceCode                 destination service/partner code
     * @param spId                        service provider SAML entity identifier
     * @param mdHandler                   metadata handler
     * @param signingKeyStoreFilePath     The file path for the keystore holding the private key we as a identity
     *                                    provider would use to sign an outbound SAML message or null.
     * @param signingKeyStoreFilePassword The password for the keystore holding the signing key or null.
     * @param signingKeyAlias             The alias of the signing key in the keystore or null;
     * @param signingKeyPassword          The password for the signing key or null.
     */
    public SAML2AssertionProducerProcessorImpl(final String metaDataFilePath,
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

    /**
     * Construct a SAML2 assertion producer processor
     *
     * @param mdProvider         metadata provider
     * @param idpId              identity provider SAML entity identifier
     * @param idpProtocol        identity provider SAML protocol to use
     * @param serviceCode        destination service/partner code
     * @param spId               service provider SAML entity identifier
     * @param mdHandler          metadata handler
     * @param sigCreator         signature creator
     * @param signingKeyAlias    The alias of the signing key in the keystore or null;
     * @param signingKeyPassword The password for the signing key or null.
     */
    public SAML2AssertionProducerProcessorImpl(final MetadataProvider mdProvider,
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
     * @see com.timepoorprogrammer.saml.impls.SAML2AssertionProducerProcessor#getEncrypter()
     */
    public AsymmetricalSessionKeySAMLEncrypter getEncrypter() {
        // Note, only SAML2 can encrypt assertions
        AsymmetricalSessionKeySAMLEncrypter encrypter = null;
        final String algorithm = mdHandler.getEncryptionAlgorithm(serviceProvider);
        if (algorithm != null) {
            final Credential encryptionCredentials = mdHandler.getEncryptionCredentials(mdProvider, spId);
            if (encryptionCredentials != null) {
                encrypter = new AsymmetricalSessionKeySAMLEncrypter(encryptionCredentials, algorithm);
            } else {
                log.debug("No public key certificate found in metadata for service provider {}, so not encrypting", spId);
            }
        } else {
            log.debug("No encryption algorithm defined in the metadata for service provider {}, so not encrypting", spId);
        }
        return encrypter;
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML2AssertionProducerProcessor#auditError(String, String)
     */
    public void auditError(String code, String details) {
        auditMessenger.auditError(code, idpId, idpProtocol, spId, details);
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML2AssertionProducerProcessor#auditSuccess(String, String)
     */
    public void auditSuccess(String code, String details) {
        auditMessenger.auditSuccess(code, idpId, idpProtocol, spId, details);
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML2AssertionProducerProcessor#createResponse(com.timepoorprogrammer.saml.core.SAML2Handler)
     */
    public Response createResponse(SAML2Handler samlHandler) {
        // Create a SAML response indicating success, who its from (the issuer details provided on
        // SAMLHandler construction), and set the destination to the remote SAML consumer service as
        // set in the destination service provider metadata.
        //
        // Note: The remote service provider will read metadata using the provider issuer name as a key
        // to lookup the identity provider configuration so it can validate the SAML response and assertion
        // it receives.
        final String destination = this.getDestination();
        Response samlResponse = samlHandler.createResponse(StatusCode.SUCCESS_URI, "AccessRequest", null);
        samlResponse.setDestination(destination);
        return samlResponse;
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML2AssertionProducerProcessor#createAuthnAssertion(com.timepoorprogrammer.saml.core.SAML2Handler, String)
     */
    public Assertion createAuthnAssertion(SAML2Handler samlHandler, String userIdentifier) {
        // Create a subject with user identifier, destination (to be added to SubjectConfirmationData) , and
        // the implementation specific timetolive
        final String destination = this.getDestination();
        final Subject subject = samlHandler.createSubject(userIdentifier, NameIDType.PERSISTENT, "bearer", destination, TIME_AFTER_IN_MINUTES);
        // Create an assertion with subject, password context, and time before (seconds), and time to live (minutes)
        return samlHandler.createAuthnAssertion(subject, AuthnContext.PPT_AUTHN_CTX,
                TIME_BEFORE_IN_SECONDS, TIME_AFTER_IN_MINUTES);
    }

    /*
   * @see SAML2AssertionProducerProcessor#createAuthnAssertion(SAML2Handler, String, java.util.Map)
     */
    public Assertion createAuthnAssertion(SAML2Handler samlHandler, String userIdentifier, Map<String, String> attributes) {
        // Create a subject with user identifier, destination (to be added to SubjectConfirmationData) , and
        // the implementation specific timetolive
        final String destination = this.getDestination();
        final Subject subject = samlHandler.createSubject(userIdentifier, NameIDType.PERSISTENT, "bearer", destination, TIME_AFTER_IN_MINUTES);
        // Create an assertion with subject, password context, and time before (seconds), and time to live (minutes)
        return samlHandler.createAuthnAssertion(subject, AuthnContext.PPT_AUTHN_CTX,
                TIME_BEFORE_IN_SECONDS, TIME_AFTER_IN_MINUTES, attributes);
    }
}