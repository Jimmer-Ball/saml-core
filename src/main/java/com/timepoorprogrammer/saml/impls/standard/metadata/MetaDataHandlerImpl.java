package com.timepoorprogrammer.saml.impls.standard.metadata;

import com.timepoorprogrammer.common.utilities.xml.XMLUtilities;
import com.timepoorprogrammer.saml.impls.MetaDataHandler;
import com.timepoorprogrammer.saml.impls.MetaDataHandler;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.*;
import org.opensaml.saml2.metadata.provider.DOMMetadataProvider;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.util.List;

/**
 * Default metadata handler implementation for reading service provider and identity provider information out of
 * shared trust information as expressed in a metadata XML file that meets the SAML2 metadata standards.
 *
 * @author Jim Ball
 */
public class MetaDataHandlerImpl implements MetaDataHandler {
    private static final Logger log = LoggerFactory.getLogger(MetaDataHandlerImpl.class);

    public MetaDataHandlerImpl() {
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.MetaDataHandler#getMetadata(String)
     */
    public MetadataProvider getMetadata(final String filePath) {
        if (filePath != null) {
            try {
                FilesystemMetadataProvider provider = new FilesystemMetadataProvider(new File(filePath));
                provider.setParserPool(new BasicParserPool());
                provider.initialize();
                return provider;
            } catch (Exception anyE) {
                final String errorMessage = "Error creating filesystem metadata provider object";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "No filepath provided";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.MetaDataHandler#getMetadata(URL)
     */
    public MetadataProvider getMetadata(final URL url) {
        if (url != null) {
            try {
                XMLUtilities xmlUtils = new XMLUtilities();
                Document metaData = xmlUtils.buildDocument(url.openStream());
                DOMMetadataProvider provider = new DOMMetadataProvider(metaData.getDocumentElement());
                provider.setParserPool(new BasicParserPool());
                provider.initialize();
                return provider;
            } catch (Exception anyE) {
                final String errorMessage = "Error creating remote URL metadata provider object";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "No URL provided";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.MetaDataHandler#getMetadata(java.io.InputStream)
     */
    public MetadataProvider getMetadata(InputStream metadataStream) {
        if (metadataStream != null) {
            try {
                XMLUtilities xmlUtils = new XMLUtilities();
                Document metaData = xmlUtils.buildDocument(metadataStream);
                DOMMetadataProvider provider = new DOMMetadataProvider(metaData.getDocumentElement());
                provider.setParserPool(new BasicParserPool());
                provider.initialize();
                return provider;
            } catch (Exception anyE) {
                final String errorMessage = "Error creating remote URL metadata provider object";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "No stream provided";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.MetaDataHandler#getIdentityProvider(org.opensaml.saml2.metadata.provider.MetadataProvider, String, String)
     */
    public IDPSSODescriptor getIdentityProvider(final MetadataProvider metadataProvider, final String identityProviderId, final String protocolType) {
        if (metadataProvider != null && identityProviderId != null && protocolType != null) {
            try {
                // By default we assume an identity provider metadata definition we process holds only one
                // identity provider descriptor.
                IDPSSODescriptor idpDescriptor = null;
                final EntityDescriptor identityProviderParentEntity = metadataProvider.getEntityDescriptor(identityProviderId);
                if (identityProviderParentEntity != null) {
                    idpDescriptor = identityProviderParentEntity.getIDPSSODescriptor(protocolType);
                }
                return idpDescriptor;
            } catch (Exception anyE) {
                final String errorMessage = "Error obtaining identity provider descriptor details";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "Cannot get identity provider descriptor, arguments missing";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * @see MetaDataHandler#getServiceProvider(org.opensaml.saml2.metadata.provider.MetadataProvider, String, String)
     */
    public SPSSODescriptor getServiceProvider(final MetadataProvider metadataProvider, final String serviceProviderId, final String protocolType) {
        if (metadataProvider != null && serviceProviderId != null) {
            try {
                SPSSODescriptor spDescriptor = null;
                final EntityDescriptor serviceProviderParentEntity = metadataProvider.getEntityDescriptor(serviceProviderId);
                if (serviceProviderParentEntity != null) {
                    spDescriptor = serviceProviderParentEntity.getSPSSODescriptor(protocolType);
                }
                return spDescriptor;
            } catch (Exception anyE) {
                final String errorMessage = "Error obtaining service provider descriptor details";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "Cannot get service provider descriptor, arguments missing";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.MetaDataHandler#getServiceProviderAssertionConsumerServiceURL(org.opensaml.saml2.metadata.SPSSODescriptor, String)
     */
    public String getServiceProviderAssertionConsumerServiceURL(final SPSSODescriptor serviceProvider, final String bindingType) {
        if (serviceProvider != null && bindingType != null) {
            try {
                String location = null;
                List<AssertionConsumerService> assertionConsumers = serviceProvider.getAssertionConsumerServices();
                if (assertionConsumers != null) {
                    for (AssertionConsumerService currentConsumer : assertionConsumers) {
                        // By default for the different sorts of bindings we assume only one consumer, as anything else
                        // would be nonsense.  So metadata for a service provider should only have one SAML2 consumer,
                        // and one SAML1.1 consumer, etc.
                        if (currentConsumer.getBinding().equals(bindingType)) {
                            location = currentConsumer.getLocation();
                            break;
                        }
                    }
                }
                return location;
            } catch (Exception anyE) {
                final String errorMessage = "Error obtaining service provider's assertion consumer service URL";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "Cannot get service provider's assertion consumer service URL, arguments missing";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.MetaDataHandler#getIdentityProviderSingleSignOnServiceURL(org.opensaml.saml2.metadata.IDPSSODescriptor)
     */
    public String getIdentityProviderSingleSignOnServiceURL(final IDPSSODescriptor identityProvider) {
        if (identityProvider != null) {
            try {
                String location = null;
                // By default we only cater for one single sign on service definition per identity provider
                List<SingleSignOnService> singleSignOnServices = identityProvider.getSingleSignOnServices();
                if (singleSignOnServices != null) {
                    final SingleSignOnService singleSignOnService = singleSignOnServices.get(0);
                    if (singleSignOnService != null) {
                        location = singleSignOnService.getLocation();
                    }
                }
                return location;
            } catch (Exception anyE) {
                final String errorMessage = "Error obtaining service provider's assertion consumer service URL";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "Cannot get identity provider's single sign on service URL, arguments missing";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.MetaDataHandler#getEncryptionAlgorithm(org.opensaml.saml2.metadata.SPSSODescriptor)
     */
    public String getEncryptionAlgorithm(final SPSSODescriptor serviceProvider) {
        if (serviceProvider != null) {
            try {
                // By default we assume a service provider holds only one key describing their encryption
                // we would be interested in.
                String encryptionAlgorithm = null;
                List<KeyDescriptor> keyDescriptors = serviceProvider.getKeyDescriptors();
                if (keyDescriptors != null && !keyDescriptors.isEmpty()) {
                    final KeyDescriptor keyDescriptor = keyDescriptors.get(0);
                    if (keyDescriptor != null) {
                        if (!keyDescriptor.getEncryptionMethods().isEmpty()) {
                            final EncryptionMethod encryptionMethod = keyDescriptor.getEncryptionMethods().get(0);
                            if (encryptionMethod != null) {
                                encryptionAlgorithm = encryptionMethod.getAlgorithm();
                            } else {
                                final String errorMessage = "Error, encryption method defined, but missing the algorithm details to apply";
                                log.error(errorMessage);
                                throw new RuntimeException(errorMessage);
                            }
                        }
                    }
                }
                return encryptionAlgorithm;
            } catch (Exception anyE) {
                final String errorMessage = "Error getting encryption algorithm from metadata";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "Missing metadataProvider or entityName, cannot lookup the encryption algorithm to apply";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * @see MetaDataHandler#getEncryptionCredentials(org.opensaml.saml2.metadata.provider.MetadataProvider, String)
     */
    public Credential getEncryptionCredentials(final MetadataProvider metadataProvider, final String serviceProviderId) {
        if (metadataProvider != null && serviceProviderId != null) {
            try {
                // Pull out the credentials from the service provider form the one key required for encryption
                MetadataCredentialResolver mdCredResolver = new MetadataCredentialResolver(metadataProvider);
                CriteriaSet encryptingCriteriaSet = new CriteriaSet();
                encryptingCriteriaSet.add(new EntityIDCriteria(serviceProviderId));
                encryptingCriteriaSet.add(new MetadataCriteria(SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
                encryptingCriteriaSet.add(new UsageCriteria(UsageType.ENCRYPTION));
                return mdCredResolver.resolveSingle(encryptingCriteriaSet);
            } catch (Exception anyE) {
                final String errorMessage = "Error getting encryption credentials from metadata";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "Missing metadataProvider or entityName, cannot lookup the encryption credentials to apply";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.MetaDataHandler#signsSAML(org.opensaml.saml2.metadata.IDPSSODescriptor)
     */
    public boolean signsSAML(final IDPSSODescriptor identityProvider) {
        if (identityProvider != null) {
            // We assume the identity provider details only come with one signing certificate, as its all we
            // need to know.
            try {
                boolean signsItsContent = false;
                List<KeyDescriptor> keyDescriptors = identityProvider.getKeyDescriptors();
                if (keyDescriptors != null && !keyDescriptors.isEmpty()) {
                    final KeyDescriptor keyDescriptor = keyDescriptors.get(0);
                    if (keyDescriptor != null) {
                        final UsageType usageType = keyDescriptor.getUse();
                        if (usageType.equals(UsageType.SIGNING)) {
                            signsItsContent = true;
                        }
                    }
                }
                return signsItsContent;
            } catch (Exception anyE) {
                final String errorMessage = "Error getting whether the identity provider signs its content from metadata";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "Missing identityProvider descriptor, cannot lookup whether it signs content or not";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * @see MetaDataHandler#getTrustEngine(org.opensaml.saml2.metadata.provider.MetadataProvider)
     */
    public ExplicitKeySignatureTrustEngine getTrustEngine(final MetadataProvider metadataProvider) {
        if (metadataProvider != null) {
            try {
                // Get any trust engine details from the metadata, so a pre-filter for signing certs in metadata
                MetadataCredentialResolver mdCredResolver = new MetadataCredentialResolver(metadataProvider);
                KeyInfoCredentialResolver keyInfoCredResolver = mdCredResolver.getKeyInfoCredentialResolver();
                return new ExplicitKeySignatureTrustEngine(mdCredResolver, keyInfoCredResolver);
            } catch (Exception anyE) {
                final String errorMessage = "Error getting trust engine from metadata";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "Missing metadataProvider, cannot lookup trust engine to apply for ";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.MetaDataHandler#getSignatureValidationCriteria(String, String)
     */
    public CriteriaSet getSignatureValidationCriteria(final String identityProviderId, final String protocolType) {
        if (identityProviderId != null && protocolType != null) {
            CriteriaSet signingCriteriaSet = new CriteriaSet();
            signingCriteriaSet.add(new EntityIDCriteria(identityProviderId));
            // We could be looking for SAML2 IdP or SAML 1.1 IdP
            signingCriteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, protocolType));
            signingCriteriaSet.add(new UsageCriteria(UsageType.SIGNING));
            return signingCriteriaSet;
        } else {
            final String errorMessage = "Error creating the Metadata search criteria needed to look for a certificate holding the public key of an IdP we use to validate a signature at a SP, missing IdP entity id or the protocol type";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }
}
