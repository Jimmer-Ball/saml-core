package com.timepoorprogrammer.saml.impls.standard.producer.processor;

import com.timepoorprogrammer.saml.impls.AuditMessenger;
import com.timepoorprogrammer.saml.impls.AuditMessengerFactory;
import com.timepoorprogrammer.saml.impls.MetaDataHandler;
import com.timepoorprogrammer.saml.security.signature.X509SAMLSignatureCreator;
import com.timepoorprogrammer.saml.impls.AuditMessenger;
import com.timepoorprogrammer.saml.impls.AuditMessengerFactory;
import com.timepoorprogrammer.saml.impls.MetaDataHandler;
import com.timepoorprogrammer.saml.security.signature.X509SAMLSignatureCreator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.xml.signature.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SAML assertion producer processor base class.
 *
 * @author Jim Ball
 */
public class SAMLAssertionProducerProcessorBase {
    private static final Logger log = LoggerFactory.getLogger(SAMLAssertionProducerProcessorBase.class);
    protected String idpId;
    protected String idpProtocol;
    protected String spId;
    protected MetaDataHandler mdHandler;
    protected MetadataProvider mdProvider;
    protected IDPSSODescriptor identityProvider;
    protected SPSSODescriptor serviceProvider;
    protected AuditMessenger auditMessenger;

    protected X509SAMLSignatureCreator sigCreator;
    private String signingKeyAlias;
    private String signingKeyPassword;

    /**
     * Construct a SAML assertion producer processor
     *
     * @param metaDataFilePath            metadata file path
     * @param idpId                       identity provider SAML entity id
     * @param idpProtocol                 identity provider SAML protocol to use
     * @param serviceCode                 destination service/partner code used for picking up a
     *                                    bespoke audit messenger
     * @param spId                        service provider SAML entity id
     * @param mdHandler                   metadata handler
     * @param signingKeyStoreFilePath     The file path for the keystore holding the private key we as a identity
     *                                    provider would use to sign an outbound SAML message or null.
     * @param signingKeyStoreFilePassword The password for the keystore holding the signing key or null.
     * @param signingKeyAlias             The alias of the signing key in the keystore or null;
     * @param signingKeyPassword          The password for the signing key or null.
     */
    public SAMLAssertionProducerProcessorBase(final String metaDataFilePath,
                                              final String idpId,
                                              final String idpProtocol,
                                              final String serviceCode,
                                              final String spId,
                                              final MetaDataHandler mdHandler,
                                              final String signingKeyStoreFilePath,
                                              final String signingKeyStoreFilePassword,
                                              final String signingKeyAlias,
                                              final String signingKeyPassword) {
        setupEntities(metaDataFilePath, idpId, idpProtocol, spId, mdHandler, signingKeyStoreFilePath,
                signingKeyStoreFilePassword, signingKeyAlias, signingKeyPassword);
        // Pickup an audit messenger which amy or may not be bespoked according to the service provider
        // we are sending to
        this.auditMessenger = AuditMessengerFactory.getInstance(serviceCode);
    }

    /**
     * Construct a SAML assertion producer processor
     *
     * @param mdProvider         meta data provider
     * @param idpId              identity provider SAML entity id
     * @param idpProtocol        identity provider SAML protocol to use
     * @param serviceCode        destination service/partner code used for picking up a
     *                           bespoke audit messenger
     * @param spId               service provider SAML entity id
     * @param mdHandler          metadata handler
     * @param sigCreator         XML signature creator
     * @param signingKeyAlias    The alias of the signing key in the keystore or null;
     * @param signingKeyPassword The password for the signing key or null.
     */
    public SAMLAssertionProducerProcessorBase(final MetadataProvider mdProvider,
                                              final String idpId,
                                              final String idpProtocol,
                                              final String serviceCode,
                                              final String spId,
                                              final MetaDataHandler mdHandler,
                                              final X509SAMLSignatureCreator sigCreator,
                                              final String signingKeyAlias,
                                              final String signingKeyPassword) {
        setupEntities(mdProvider, idpId, idpProtocol, spId, mdHandler, sigCreator, signingKeyAlias, signingKeyPassword);
        this.auditMessenger = AuditMessengerFactory.getInstance(serviceCode);
    }

    /**
     * Finish the blank signature provided.
     *
     * @param blankSignature blank signature
     */
    public void finishSignature(Signature blankSignature) {
        if (sigCreator != null && signingKeyAlias != null && signingKeyPassword != null) {
            sigCreator.finishSignature(blankSignature, signingKeyAlias, signingKeyPassword);
        }
    }

    /**
     * Get the target ServiceProvider destination URL as defined in metadata against the AssertionConsumerService on
     * the remote service provider that meets the protocol this identity provider is using.
     * <p/>
     * This value is key.  If the assertion arrives at the target destination assertion consumer
     * service and the then locally derived URL for the assertion consumer does not resolve to this value
     * then the assertion consumer service will reject the assertion out of hand.  This is what
     * the specification intends, and what OpenSAML does for us behind the scenes.  So setting this
     * URL in the metadata means understanding that the public address of an assertion consumer can
     * be matched locally by the assertion consumer itself on reception of an assertion.  This usally
     * means a dialogue with the hosting team to confirm what the assertion consumer URL should be
     * BEFORE sending any service provider metadata out to a customer.
     * <p/>
     * The consequence of this is two sets of metadata.  One we send to the customer holding the "public"
     * URL their infrastructure sends to, to reach our SAML middleware assertion consumers, and one we keep
     * locally at the middleware, as by the time the request reaches the middleware in hosting, the URL will
     * have been rewritten and amended to a "local" URL by the proxy and load balancing infrastructure in
     * front of the middleware.
     *
     * @return destination
     */
    public String getDestination() {
        String destination;
        if (idpProtocol.equals(SAMLConstants.SAML20P_NS)) {
            destination = mdHandler.getServiceProviderAssertionConsumerServiceURL(serviceProvider,
                    SAMLConstants.SAML2_POST_BINDING_URI);
        } else {
            destination = mdHandler.getServiceProviderAssertionConsumerServiceURL(serviceProvider,
                    SAMLConstants.SAML1_POST_BINDING_URI);
        }
        if (destination != null) {
            return destination;
        } else {
            final String errorMessage = "The metadata for the target destination service provider " +
                    spId + " is missing an assertion consumer binding that adheres to the protocol " + idpProtocol +
                    " meaning we, as an IdP, cannot send our assertion to the intended destination, as " +
                    " the destination doesn't have an ingress point that can cope with our standard of SAML.";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * Setup the entities required for a producer.
     *
     * @param metaDataFilePath            metadata file path
     * @param idpId                       identity provider id
     * @param idpProtocol                 identity provider SAML protocol to use
     * @param spId                        service provider id
     * @param mdHandler                   metadata handler
     * @param signingKeyStoreFilePath     The file path for the keystore holding the private key we as a identity
     *                                    provider would use to sign an outbound SAML message or null.
     * @param signingKeyStoreFilePassword The password for the keystore holding the signing key or null.
     * @param signingKeyAlias             The alias of the signing key in the keystore or null;
     * @param signingKeyPassword          The password for the signing key or null.
     */
    protected void setupEntities(final String metaDataFilePath,
                                 final String idpId,
                                 final String idpProtocol,
                                 final String spId,
                                 final MetaDataHandler mdHandler,
                                 final String signingKeyStoreFilePath,
                                 final String signingKeyStoreFilePassword,
                                 final String signingKeyAlias,
                                 final String signingKeyPassword) {
        if (metaDataFilePath != null && idpId != null && idpProtocol != null && spId != null && mdHandler != null) {
            this.idpId = idpId;
            this.idpProtocol = idpProtocol;
            this.spId = spId;
            this.mdHandler = mdHandler;
            this.mdProvider = mdHandler.getMetadata(metaDataFilePath);

            // Check we have a destination service provider to send to defined in metadata
            this.serviceProvider = mdHandler.getServiceProvider(this.mdProvider, spId, idpProtocol);
            if (this.serviceProvider == null) {
                final String errorMessage = "Unable to read service provider details for SP " +
                        spId + " from metadata";
                log.error(errorMessage);
                throw new RuntimeException(errorMessage);
            }

            // Check we have our own (identity provider) details in metadata
            this.identityProvider = mdHandler.getIdentityProvider(this.mdProvider, idpId, idpProtocol);
            if (this.identityProvider == null) {
                final String errorMessage = "Unable to read identity provider details for IdP " +
                        idpId + " with protocol " + idpProtocol + " from metadata";
                log.error(errorMessage);
                throw new RuntimeException(errorMessage);
            }

            // Setup identity provider signature if signature location and access details given
            if (signingKeyStoreFilePath != null && signingKeyStoreFilePassword != null && signingKeyAlias != null && signingKeyPassword != null) {
                this.signingKeyAlias = signingKeyAlias;
                this.signingKeyPassword = signingKeyPassword;
                sigCreator = new X509SAMLSignatureCreator(signingKeyStoreFilePath, signingKeyStoreFilePassword);
            }
        }
    }

    /**
     * Setup the SAML entities needed for sending SAML assertions
     *
     * @param mdProvider         metadata provider
     * @param idpId              identity provider SAML entity identifier (source of assertion)
     * @param idpProtocol        SAMl protocol applied
     * @param spId               service provider SAML entity identifier (service provider)
     * @param mdHandler          metadata handler
     * @param sigCreator         signature creator
     * @param signingKeyAlias    signing key alias
     * @param signingKeyPassword signing key password
     */
    protected void setupEntities(final MetadataProvider mdProvider,
                                 final String idpId,
                                 final String idpProtocol,
                                 final String spId,
                                 final MetaDataHandler mdHandler,
                                 final X509SAMLSignatureCreator sigCreator,
                                 final String signingKeyAlias,
                                 final String signingKeyPassword) {
        if (mdProvider == null || idpId == null || idpProtocol == null || spId == null
                | mdHandler == null) {
            throw new IllegalArgumentException("Cannot construct a SAML assertion producer base without mandatory " +
            "settings for the mdProvider, idpId, idpProtocol, spId, and mdHandler");
        }
        this.mdProvider = mdProvider;
        this.idpId = idpId;
        this.idpProtocol = idpProtocol;
        this.spId = spId;
        this.mdHandler = mdHandler;
        this.serviceProvider = setupServiceProvider();
        if (this.serviceProvider == null) {
            throw new RuntimeException("Service Provider " + spId + " details not found in metadata");
        }
        this.identityProvider = setupIdentityProvider();
        if (this.identityProvider == null) {
            throw new RuntimeException("Identity Provider " + idpId + "details not found in metadata");
        }
        this.signingKeyAlias = signingKeyAlias;
        this.signingKeyPassword = signingKeyPassword;
        this.sigCreator = sigCreator;
    }

    protected SPSSODescriptor setupServiceProvider() {
        return mdHandler.getServiceProvider(this.mdProvider, spId, idpProtocol);
    }

    protected IDPSSODescriptor setupIdentityProvider() {
        return mdHandler.getIdentityProvider(this.mdProvider, idpId, idpProtocol);
    }
}                  
