package com.timepoorprogrammer.saml.impls.standard.consumer.processor;

import com.timepoorprogrammer.saml.impls.AuditMessenger;
import com.timepoorprogrammer.saml.impls.AuditMessengerFactory;
import com.timepoorprogrammer.saml.impls.MetaDataHandler;
import com.timepoorprogrammer.saml.impls.AuditMessenger;
import com.timepoorprogrammer.saml.impls.AuditMessengerFactory;
import com.timepoorprogrammer.saml.impls.MetaDataHandler;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SAML assertion consumer processor base class.
 *
 * @author Jim Ball
 */
public class SAMLAssertionConsumerProcessorBase {
    private static final Logger log = LoggerFactory.getLogger(SAMLAssertionConsumerProcessorBase.class);
    protected String idpId;
    protected String customerCode;
    protected String idpProtocol;
    protected String spId;
    protected MetaDataHandler mdHandler;
    protected MetadataProvider mdProvider;
    protected IDPSSODescriptor identityProvider;
    protected SPSSODescriptor serviceProvider;
    protected AuditMessenger auditMessenger;

    /**
     * Construct a SAML assertion consumer processor base passing the following arguments
     *
     * @param metaDataFilePath metadata file path
     * @param idpId            identity provider SAML entity identifier
     * @param customerCode     identity provider internal Northgate customer code used to pickup a bespoke audit
     *                         messenger and SAML response and assertion validators
     * @param idpProtocol      identity provider SAML protocol to use
     * @param spId             service provider SAML entity identifier
     * @param mdHandler        metadata handler
     */
    public SAMLAssertionConsumerProcessorBase(final String metaDataFilePath,
                                              final String idpId,
                                              final String customerCode,
                                              final String idpProtocol,
                                              final String spId,
                                              final MetaDataHandler mdHandler) {
        setupEntities(metaDataFilePath, idpId, idpProtocol, spId, mdHandler);
        this.customerCode = customerCode;
        // Pick up an audit messenger which may or may not be bespoked according to customer code
        auditMessenger = AuditMessengerFactory.getInstance(this.customerCode);
    }

    /**
     * Construct a SAML assertion consumer processor base passing the following arguments
     *
     * @param mdProvider   metadata provider
     * @param idpId        identity provider SAML entity identifier
     * @param customerCode identity provider internal Northgate customer code used for pickling up a bespoke
     *                     audit messenger and SAML response and assertion validators
     * @param idpProtocol  identity provider SAML protocol to use
     * @param spId         service provider SAML entity identifier
     * @param mdHandler    metadata handler
     */
    public SAMLAssertionConsumerProcessorBase(final MetadataProvider mdProvider,
                                              final String idpId,
                                              final String customerCode,
                                              final String idpProtocol,
                                              final String spId,
                                              final MetaDataHandler mdHandler) {
        setupEntities(mdProvider, idpId, idpProtocol, spId, mdHandler);
        this.customerCode = customerCode;
        // Pick up an audit messenger which may or may not be bespoked according to customer code
        auditMessenger = AuditMessengerFactory.getInstance(this.customerCode);
    }

    /**
     * Does our remote IDP sign its messages according to our metadata?
     *
     * @return true if the IDP signs messages false otherwise
     */
    public boolean idpSignsMessages() {
        return mdHandler.signsSAML(identityProvider);
    }

    /**
     * Is the provided signature any good?
     *
     * @param signature signature
     * @return true if good false otherwise
     */
    public boolean isSignatureGood(final Signature signature) {
        if (signature != null) {
            try {
                log.debug("Issuer " + idpId + " signs its SAML content according to our shared metadata, checking signature");
                // Create a trust engine and signature validation criteria given the issuer
                ExplicitKeySignatureTrustEngine trustEngine = mdHandler.getTrustEngine(mdProvider);
                CriteriaSet sigValidationCriteria = mdHandler.getSignatureValidationCriteria(idpId, idpProtocol);
                // Check the signature given the metadata and the signature validation criteria
                return trustEngine.validate(signature, sigValidationCriteria);
            } catch (Exception anyE) {
                final String errorMessage = "Error checking signature";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "Signature is missing from message";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * Setup the identity provider and service provider details.
     *
     * @param metaDataFilePath metadata file path
     * @param idpId            identity provider id
     * @param idpProtocol      identity provider protocol
     * @param spId             service provider id
     * @param mdHandler        metadata handler
     */
    protected void setupEntities(final String metaDataFilePath, final String idpId,
                                 final String idpProtocol, final String spId,
                                 final MetaDataHandler mdHandler) {
        if (metaDataFilePath != null && idpId != null && idpProtocol != null && spId != null && mdHandler != null) {
            this.idpId = idpId;
            this.idpProtocol = idpProtocol;
            this.spId = spId;
            this.mdHandler = mdHandler;
            this.mdProvider = mdHandler.getMetadata(metaDataFilePath);
            this.serviceProvider = mdHandler.getServiceProvider(mdProvider, spId, idpProtocol);
            if (this.serviceProvider == null) {
                final String errorMessage = "Unable to read service provider details for SP " + spId + " from metadata";
                log.error(errorMessage);
                throw new RuntimeException(errorMessage);
            }
            this.identityProvider = mdHandler.getIdentityProvider(mdProvider, idpId, idpProtocol);
            if (this.identityProvider == null) {
                final String errorMessage = "Unable to read identity provider details for IdP " +
                        idpId + " with protocol " + idpProtocol + " from metadata";
                log.error(errorMessage);
                throw new RuntimeException(errorMessage);
            }
        } else {
            final String errorMessage = "Missing required arguments, cannot construct AssertionConsumerProcessor";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * Setup the identity provider and service provider details.
     *
     * @param mdProvider  metadata provider
     * @param idpId       identity provider id
     * @param idpProtocol identity provider protocol
     * @param spId        service provider id
     * @param mdHandler   metadata handler
     */
    protected void setupEntities(final MetadataProvider mdProvider, final String idpId,
                                 final String idpProtocol, final String spId,
                                 final MetaDataHandler mdHandler) {
        if (mdProvider == null || idpId == null || idpProtocol == null || spId == null || mdHandler == null) {
            throw new IllegalArgumentException(("Cannot construct a SAML assertion consumer base without mandatory " +
                    "settings for the mdProvider, idpId, idpProtocol, spId, and mdHandler"));
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
    }

    protected SPSSODescriptor setupServiceProvider() {
        return mdHandler.getServiceProvider(this.mdProvider, spId, idpProtocol);
    }

    protected IDPSSODescriptor setupIdentityProvider() {
        return mdHandler.getIdentityProvider(this.mdProvider, idpId, idpProtocol);
    }
}