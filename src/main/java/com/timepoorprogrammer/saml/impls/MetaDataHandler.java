package com.timepoorprogrammer.saml.impls;

import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;

import java.io.InputStream;
import java.net.URL;

/**
 * Handler for our metadata describing trust relationships
 * between Identity Providers (IdPs) and Service Provider (SPs).
 *
 * @author Jim Ball
 */
public interface MetaDataHandler {
    /**
     * Get a handle to our metadata given the input file path
     * <p/>
     * This is used by both SAMLAssertionProducers and SAMLAssertionConsumers to access their
     * shared metadata describing their mutual federation, regardless of whether the metadata
     * describes both the IdP and the SP in the same file.
     * <p/>
     * This object is dynamic.  If you change the content of the metadata, this object can cope,
     * you don't need to stop the system to amend the metadata.
     *
     * @param filePath path to metadata XML file
     * @return MetadataProvider
     */
    public MetadataProvider getMetadata(final String filePath);

    /**
     * Get a handle to our metadata given the input URL
     * <p/>
     * This is used by both SAMLAssertionProducers and SAMLAssertionConsumers to access their
     * shared metadata describing their mutual federation, regardless of whether the metadata
     * describes both the IdP and the SP in the same file.
     * <p/>
     * This object is dynamic.  If you change the content of the metadata, this object can cope,
     * you don't need to stop the system to amend the metadata.
     *
     * @param resource URL to metadata XMl file
     * @return MetadataProvider
     */
    public MetadataProvider getMetadata(final URL resource);

    /**
     * Get a handle to our metadata given the input stream
     * <p/>
     * This is used by both SAMLAssertionProducers and SAMLAssertionConsumers to access their
     * shared metadata describing their mutual federation, regardless of whether the metadata
     * describes both the IdP and the SP in the same file.
     * <p/>
     * This object is dynamic.  If you change the content of the metadata, this object can cope,
     * you don't need to stop the system to amend the metadata.
     *
     * @param metadataStream input stream
     * @return MetadataProvider
     */
    public MetadataProvider getMetadata(InputStream metadataStream);


    /**
     * Get the identity provider details from metadata given their identifier and the type of SAML they support
     *
     * @param metadataProvider   metadata provider
     * @param identityProviderId identity provider id
     * @param protocolType       either SAML2 so, "urn:oasis:names:tc:SAML:2.0:protocol" or SAML1.1 so
     *                           "urn:oasis:names:tc:SAML:1.1:protocol"
     * @return identity provider descriptor from metadata or null if not found
     */
    public IDPSSODescriptor getIdentityProvider(final MetadataProvider metadataProvider, final String identityProviderId, final String protocolType);

    /**
     * Get the service provider details from metadata given their identifer and the protocol type we are expecting
     * them to support
     *
     * @param metadataProvider  metadata provider
     * @param serviceProviderId service provider id
     * @param protocolType      either SAML2 so, "urn:oasis:names:tc:SAML:2.0:protocol" or SAML1.1 so
     *                          "urn:oasis:names:tc:SAML:1.1:protocol"
     * @return service provider descriptor from metadata or null if not found
     */
    public SPSSODescriptor getServiceProvider(final MetadataProvider metadataProvider, final String serviceProviderId, final String protocolType);

    /**
     * Get the URL for the service provider's assertion consumer service from metadata given the binding type.  We have
     * different AssertionConsumerServices for different flavours of SAML each with a target URL.
     *
     * @param serviceProvider service provider descriptor
     * @param bindingType     The binding type (so SAML2 post binding, SAML1.1 browser post, etc) that defines the kind of
     *                        messaging ot send the consumer, so SAML2, SAML1.1, etc.
     * @return destination URL for the service provider's assertion consumer service
     */
    public String getServiceProviderAssertionConsumerServiceURL(final SPSSODescriptor serviceProvider, final String bindingType);

    /**
     * Get the URL for the identity provider's single sign on service from metadata
     *
     * @param identityProvider identity provider
     * @return destination URL for the identity provider's single sign on service
     */
    public String getIdentityProviderSingleSignOnServiceURL(final IDPSSODescriptor identityProvider);

    /**
     * Get the encryption algorithm to apply to outbound SAML messages for a particular Service Provider.
     * <p/>
     * It is the Service Provider's way of saying, make sure you encrypt messages thus when you send them to me.
     * <p/>
     * This method is usually used by a SAMLAssertionProducer.
     *
     * @param serviceProvider service provider descriptor
     * @return the encryption algorithm to use as per XMLSig standards or null if no encryption expected
     */
    public String getEncryptionAlgorithm(final SPSSODescriptor serviceProvider);

    /**
     * Get the encryption credentials to apply for outbound SAML messages to a particular Service Provider.
     * This returns the credentials derived from the certificate held in a Service Provider's entity description
     * in the metadata.
     * <p/>
     * This method is usually used by a SAMLAssertionProducer, and is only applicable if an encryption method has
     * been defined, else it will return null.
     *
     * @param metadataProvider  metadata provider descriptor
     * @param serviceProviderId service provider identifier
     * @return Credentials to apply to encryption or null if no encryption expected
     */
    public Credential getEncryptionCredentials(final MetadataProvider metadataProvider, final String serviceProviderId);

    /**
     * Does the identity provider sign the SAML it sends or not, as extracted from metadata.
     *
     * @param identityProvider identity provider
     * @return true if it does/false if it doesn't
     */
    public boolean signsSAML(final IDPSSODescriptor identityProvider);

    /**
     * Get the trust engine to apply for checking the signature of incoming SAML messages for SAML.
     * <p/>
     * This method is usually used by a SAMLAssertionConsumer.
     *
     * @param metadataProvider metadataProvider
     * @return trust engine we can use to verify a signed SAML message or null
     */
    public ExplicitKeySignatureTrustEngine getTrustEngine(final MetadataProvider metadataProvider);

    /**
     * Get the search parameters (criteria set) a service provider would use to filter metadata in order to
     * obtain the certificate details provided by an identity provider for SAML.  The identity provider signs a
     * SAMLMessage using their private key, and a target service provider uses the public key it
     * extracts from the certificate provided by the identity provider to validate the signature.
     * <p/>
     * This tells the service provider the SAMLMessage has not been messed about with in transit.
     *
     * @param identityProviderId The identity provider id
     * @param protocolType       either SAML2 so, "urn:oasis:names:tc:SAML:2.0:protocol" or SAML1.1 so
     *                           "urn:oasis:names:tc:SAML:1.1:protocol"
     * @return the critiera set to use for filtering the metadata to get the certificate holding the
     *         identity provider's public key, which will allow the service provider to validate the signature or null
     *         if no signature criteria can be found, or null if no signing of SAML is expected
     */
    public CriteriaSet getSignatureValidationCriteria(final String identityProviderId, final String protocolType);
}
