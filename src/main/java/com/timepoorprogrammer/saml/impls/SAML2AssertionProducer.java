package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.common.AuditMessages;
import com.timepoorprogrammer.saml.configuration.ConfigurationProperties;
import com.timepoorprogrammer.saml.configuration.EntityTranslation;
import com.timepoorprogrammer.saml.configuration.ProducerConfiguration;
import com.timepoorprogrammer.saml.core.SAML2Handler;
import com.timepoorprogrammer.saml.core.SAMLHelper;
import com.timepoorprogrammer.saml.impls.standard.producer.processor.SAML2AssertionProducerProcessorImpl;
import com.timepoorprogrammer.saml.security.encryption.AsymmetricalSessionKeySAMLEncrypter;
import com.timepoorprogrammer.saml.security.signature.X509SAMLSignatureCreator;
import com.timepoorprogrammer.saml.common.AuditMessages;
import com.timepoorprogrammer.saml.core.SAML2Handler;
import com.timepoorprogrammer.saml.security.signature.X509SAMLSignatureCreator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import java.io.InputStream;
import java.net.URL;
import java.util.Map;
import java.util.Properties;

/**
 * Simplified encapsulation of a SAML2 assertion producer for use by any of our applications that will use
 * a default SAML2AssertionProducerProcessor.
 * <p/>
 * If you want to do more complicated things you may need to write a bespoke implementation that meets the rules
 * outlined in the SAML2AssertionProducerProcessorFactory.
 *
 * @author Jim Ball
 */
public class SAML2AssertionProducer {
    private ConfigurationProperties configurationProperties;
    private ProducerConfiguration producerConfiguration;
    private EntityTranslation entityTranslation;
    private SAML2Handler samlHandler;
    private MetaDataHandler mdHandler;
    private SAML2AssertionProducerProcessor processor;
    private MetadataProvider mdProvider;
    X509SAMLSignatureCreator sigCreator;

    /**
     * Setup an assertion producer from file paths
     *
     * @param producerCode                producer code (e.g. myViewSalesForceClient) that identifies configuration in config file
     * @param serviceCode                 service code (e.g. salesForceService) that identifies a remote service.
     * @param saml2Handler                SAML2Handler.  There only needs to be one of these per client, as they are expensive to make
     * @param configurationPropertiesPath Path to SAML configuration file See saml.properties. In this the paths to the
     *                                    SAML metadata and encryption files live
     * @param entityTranslationPropertiesPath
     *                                    Path to translation file for going from serviceCode to public SAML entity
     *                                    identifier and back again. See samlentitytranslation.properties.
     * @param metaDataPath                Path to SAML metadata
     * @param privateKeyStorePath         Path to private key store used for digital signatures nmay be null if
     *                                    no signing to be done
     */
    public SAML2AssertionProducer(final String producerCode,
                                  final String serviceCode,
                                  final SAML2Handler saml2Handler,
                                  final String configurationPropertiesPath,
                                  final String entityTranslationPropertiesPath,
                                  final String metaDataPath,
                                  final String privateKeyStorePath) {
        if (producerCode == null || serviceCode == null || saml2Handler == null
                || configurationPropertiesPath == null || entityTranslationPropertiesPath == null
                || metaDataPath == null) {
            throw new IllegalArgumentException("Missing producer code, service code, SAML2 handler, and properties");
        }
        samlHandler = saml2Handler;
        configurationProperties = new ConfigurationProperties(configurationPropertiesPath);
        entityTranslation = new EntityTranslation(entityTranslationPropertiesPath);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        mdProvider = mdHandler.getMetadata(metaDataPath);
        final String issuer = entityTranslation.lookupEntityIdentifierUsingInternalCode(producerCode);
        samlHandler.setIssuer(issuer);
        final String serviceIdentifier = entityTranslation.lookupEntityIdentifierUsingInternalCode(serviceCode);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        final String overriddenProducerCode = this.configurationProperties.getProducerCode(producerCode);
        producerConfiguration = new ProducerConfiguration(this.configurationProperties, overriddenProducerCode);
        final String privateKeyStorePassword = producerConfiguration.getKeyStorePassword();
        sigCreator = SAMLHelper.createSignatureCreator(privateKeyStorePath, privateKeyStorePassword);
        processor = new SAML2AssertionProducerProcessorImpl(mdProvider, issuer, SAMLConstants.SAML20P_NS,
                serviceCode, serviceIdentifier, mdHandler, sigCreator,
                producerConfiguration.getSigningKeyAlias(), producerConfiguration.getSigningKeyPassword());
    }

    /**
     * Setup an assertion producer from URLs
     *
     * @param producerCode                   producer code (e.g. myViewSalesForceClient) that identifies configuration in config file
     * @param serviceCode                    service code (e.g. salesForceService) that identifies a remote service.
     * @param saml2Handler                   SAML2Handler.  There only needs to be one of these per client, as they are expensive to make
     * @param configurationPropertiesURL     SAML configuration file URL.  See saml.properties. In this the paths to the SAML metadata
     *                                       and encryption files live
     * @param entityTranslationPropertiesURL URL for Translation file for going from serviceCode to public SAML entity
     *                                       identifier and back again. See samlentitytranslation.properties.
     * @param metaDataURL                    URL to SAML metadata
     * @param privateKeyStoreURL             URL to private key store used for digital signatures may be null if no signing to
     *                                       be done
     */
    public SAML2AssertionProducer(final String producerCode,
                                  final String serviceCode,
                                  final SAML2Handler saml2Handler,
                                  final URL configurationPropertiesURL,
                                  final URL entityTranslationPropertiesURL,
                                  final URL metaDataURL,
                                  final URL privateKeyStoreURL) {
        if (producerCode == null || serviceCode == null || saml2Handler == null
                || configurationPropertiesURL == null || entityTranslationPropertiesURL == null || metaDataURL == null) {
            throw new IllegalArgumentException("Missing producer code, service code, SAML2 handler, and properties");
        }
        samlHandler = saml2Handler;
        configurationProperties = new ConfigurationProperties(configurationPropertiesURL);
        entityTranslation = new EntityTranslation(entityTranslationPropertiesURL);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        mdProvider = mdHandler.getMetadata(metaDataURL);
        final String issuer = entityTranslation.lookupEntityIdentifierUsingInternalCode(producerCode);
        samlHandler.setIssuer(issuer);
        final String serviceIdentifier = entityTranslation.lookupEntityIdentifierUsingInternalCode(serviceCode);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        final String overriddenProducerCode = this.configurationProperties.getProducerCode(producerCode);
        producerConfiguration = new ProducerConfiguration(this.configurationProperties, overriddenProducerCode);
        final String privateKeyStorePassword = producerConfiguration.getKeyStorePassword();
        sigCreator = SAMLHelper.createSignatureCreator(privateKeyStoreURL, privateKeyStorePassword);
        processor = new SAML2AssertionProducerProcessorImpl(mdProvider, issuer, SAMLConstants.SAML20P_NS,
                serviceCode, serviceIdentifier, mdHandler, sigCreator,
                producerConfiguration.getSigningKeyAlias(), producerConfiguration.getSigningKeyPassword());
    }

    /**
     * Create a SAML2 Assertion Producer where the properties have been calculated via injection
     *
     * @param producerCode                producer code (e.g. myViewSalesForceClient) that identifies configuration in config file
     * @param serviceCode                 service code (e.g. salesForceService) that identifies a remote service.
     * @param saml2Handler                SAML2Handler.  There only needs to be one of these per client, as they are expensive to make
     * @param configProperties            SAML configuration properties. See saml.properites
     * @param entityTranslationProperties Properties for translation file for going from serviceCode to public SAML entity
     *                                    identifier and back again. See samlentitytranslation.properties.
     * @param metaDataPath                Path to SAML metadata
     * @param privateKeyStorePath         Path to private key store used for digital signatures
     */
    public SAML2AssertionProducer(final String producerCode,
                                  final String serviceCode,
                                  final SAML2Handler saml2Handler,
                                  final Properties configProperties,
                                  final Properties entityTranslationProperties,
                                  final String metaDataPath,
                                  final String privateKeyStorePath) {
        if (producerCode == null || serviceCode == null || saml2Handler == null
                || configProperties == null || entityTranslationProperties == null
                || metaDataPath == null) {
            throw new IllegalArgumentException("Missing producer code, service code, SAML2 handler, and properties");
        }
        samlHandler = saml2Handler;
        configurationProperties = new ConfigurationProperties(configProperties);
        entityTranslation = new EntityTranslation(entityTranslationProperties);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        mdProvider = mdHandler.getMetadata(metaDataPath);
        final String issuer = entityTranslation.lookupEntityIdentifierUsingInternalCode(producerCode);
        samlHandler.setIssuer(issuer);
        final String serviceIdentifier = entityTranslation.lookupEntityIdentifierUsingInternalCode(serviceCode);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        final String overriddenProducerCode = this.configurationProperties.getProducerCode(producerCode);
        producerConfiguration = new ProducerConfiguration(this.configurationProperties, overriddenProducerCode);
        final String privateKeyStorePassword = producerConfiguration.getKeyStorePassword();
        sigCreator = SAMLHelper.createSignatureCreator(privateKeyStorePath, privateKeyStorePassword);
        processor = new SAML2AssertionProducerProcessorImpl(mdProvider, issuer, SAMLConstants.SAML20P_NS,
                serviceCode, serviceIdentifier, mdHandler, sigCreator,
                producerConfiguration.getSigningKeyAlias(), producerConfiguration.getSigningKeyPassword());
    }

    /**
     * Setup an assertion producer from streams
     *
     * @param producerCode                  producer code (e.g. myViewSalesForceClient) that identifies configuration in config file
     * @param serviceCode                   service code (e.g. salesForceService) that identifies a remote service.
     * @param saml2Handler                  SAML2Handler.  There only needs to be one of these per client, as they are expensive to make
     * @param configurationPropertiesStream Stream to SAML configuration file See saml.properties. In this the paths to the
     *                                      SAML metadata and encryption files live
     * @param entityTranslationPropertiesStream
     *                                      Stream to translation file for going from serviceCode to public SAML entity
     *                                      identifier and back again. See samlentitytranslation.properties.
     * @param metaDataStream                Stream to SAML metadata
     * @param privateKeyStoreStream         Stream to private key store used for digital signatures nmay be null if
     *                                      no signing to be done
     */
    public SAML2AssertionProducer(final String producerCode,
                                  final String serviceCode,
                                  final SAML2Handler saml2Handler,
                                  InputStream configurationPropertiesStream,
                                  InputStream entityTranslationPropertiesStream,
                                  InputStream metaDataStream,
                                  InputStream privateKeyStoreStream) {
        if (producerCode == null || serviceCode == null || saml2Handler == null
                || configurationPropertiesStream == null || entityTranslationPropertiesStream == null
                || metaDataStream == null) {
            throw new IllegalArgumentException("Missing producer code, service code, SAML2 handler, and properties");
        }
        samlHandler = saml2Handler;
        configurationProperties = new ConfigurationProperties(configurationPropertiesStream);
        entityTranslation = new EntityTranslation(entityTranslationPropertiesStream);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        mdProvider = mdHandler.getMetadata(metaDataStream);
        final String issuer = entityTranslation.lookupEntityIdentifierUsingInternalCode(producerCode);
        samlHandler.setIssuer(issuer);
        final String serviceIdentifier = entityTranslation.lookupEntityIdentifierUsingInternalCode(serviceCode);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        final String overriddenProducerCode = this.configurationProperties.getProducerCode(producerCode);
        producerConfiguration = new ProducerConfiguration(this.configurationProperties, overriddenProducerCode);
        final String privateKeyStorePassword = producerConfiguration.getKeyStorePassword();
        sigCreator = SAMLHelper.createSignatureCreator(privateKeyStoreStream, privateKeyStorePassword);
        processor = new SAML2AssertionProducerProcessorImpl(mdProvider, issuer, SAMLConstants.SAML20P_NS,
                serviceCode, serviceIdentifier, mdHandler, sigCreator,
                producerConfiguration.getSigningKeyAlias(), producerConfiguration.getSigningKeyPassword());
    }

    /**
     * Get the SAML assertion processor, as you can do lots of things with it yourself.
     *
     * @return SAML assertion processor
     */
    public SAML2AssertionProducerProcessor getProcessor() {
        return processor;
    }

    /**
     * Get details of the producer configuration
     *
     * @return producer configuration details
     */
    public ProducerConfiguration getProducerConfiguration() {
        return producerConfiguration;
    }

    /**
     * Return the destination endpoint URL for the target service given the metadata
     *
     * @return destination end point URL
     */
    public String getDestinationEndpointURL() {
        return processor.getDestination();
    }

    /**
     * Get the encoded string that need to be placed inside the request body sent to the remote service in order
     * to "send" a SAML assertion.
     * <p/>
     * Note.  All the things done in here can be done by you locally, but you would need to build the assertion,
     * response, and encrypt and then sign the payload yourself instead of relying on this method to do it all
     * for you.
     * <p/>
     * If you are sending yourself, you need to POST a form to "send" the results of this method, for example
     * <p/>
     * <form id="senderForm" action="<c:out value="${sessionScope.destination}"/>" method="POST">
     * <input type="hidden" name="SAMLResponse" value="<c:out value="${sessionScope.SAMLResponsePayload}"/>"/>
     * <c:if test="${not empty sessionScope.RelayState}">
     * <input type="hidden" name="RelayState" value="<c:out value="${sessionScope.RelayState}"/>"/>
     * </c:if>
     * <input type="submit" id="sendResponse" name="sendResponse" value="Send Response">
     * </form>
     * <p/>
     * The values for the contents of this posted form are:
     * <p/>
     * 1) The destination is obtained from a call to getProcessor.getDestination()
     * 2) The SAMLResponse is the results of this call
     * 3) The hidden field RelayState is the name of the module within the remote application you want to
     * "deep-dive" into. Its not part of the main SAML payload, never has been.
     * <p/>
     * Don't change the names of the two input fields SAMLResponse and RelayState on your form.  These are expected to
     * be named as such, and if you change them then you won't be meeting the SAML specifications, and will probably
     * break the far end.
     *
     * @param userIdentifier user identifier
     * @return Base64 encoded string holding the SAMLResponse payload to send across to a remote service whose
     *         destination will be getProcessor().getDestination()
     */
    public String getSAMLResponsePayload(final String userIdentifier) {
        return getSAMLResponsePayload(userIdentifier, null);
    }

    /**
     * Get the SAML response payload, encrypting and signing as we go or not, as the case may be.
     *
     * @param userIdentifier user identifier
     * @param attributes     attributes
     * @return encoded payload
     */
    public String getSAMLResponsePayload(final String userIdentifier, Map<String, String> attributes) {
        Element elem = getSAMLResponseAsXML(userIdentifier, attributes);
        final String samlResponseString = XMLHelper.nodeToString(elem);
        return Base64.encodeBytes(samlResponseString.getBytes());
    }

    /**
     * Get the SAML response payload as XML (encrypted or signed as the case may be).
     *
     * @param userIdentifier user identifier
     * @param attributes     attributes
     * @return XML element
     */
    public Element getSAMLResponseAsXML(final String userIdentifier, Map<String, String> attributes) {
        try {
            final Assertion assertion = processor.createAuthnAssertion(samlHandler, userIdentifier, attributes);
            final Response samlResponse = processor.createResponse(samlHandler);
            Element elem;
            final AsymmetricalSessionKeySAMLEncrypter encrypter = processor.getEncrypter();
            if (encrypter != null) {
                EncryptedAssertion encryptedAssertion = encrypter.encryptAssertion(assertion);
                samlResponse.getEncryptedAssertions().add(encryptedAssertion);
                if (sigCreator != null) {
                    Signature signature = (Signature) samlHandler.create(Signature.DEFAULT_ELEMENT_NAME);
                    processor.finishSignature(signature);
                    if (signature != null) {
                        samlResponse.setSignature(signature);
                        elem = Configuration.getMarshallerFactory().getMarshaller(samlResponse).marshall(samlResponse);
                        Signer.signObject(signature);
                    } else {
                        final String errorDetails = AuditMessages.ProducerCode.PRODUCER_GENERIC_ERROR.getDetailsPattern() + " Failure finishing signature";
                        throw new RuntimeException(errorDetails);
                    }
                } else {
                    // Payload will be unsigned and will hold an encrypted assertion
                    elem = Configuration.getMarshallerFactory().getMarshaller(samlResponse).marshall(samlResponse);
                }
            } else {
                samlResponse.getAssertions().add(assertion);
                if (sigCreator != null) {
                    Signature signature = (Signature) samlHandler.create(Signature.DEFAULT_ELEMENT_NAME);
                    processor.finishSignature(signature);
                    if (signature != null) {
                        samlResponse.setSignature(signature);
                        elem = Configuration.getMarshallerFactory().getMarshaller(samlResponse).marshall(samlResponse);
                        Signer.signObject(signature);
                    } else {
                        final String errorDetails = AuditMessages.ProducerCode.PRODUCER_GENERIC_ERROR.getDetailsPattern() + " Failure finishing signature";
                        throw new RuntimeException(errorDetails);
                    }
                } else {
                    // Payload will be unsigned and will hold an unencrypted assertion
                    elem = Configuration.getMarshallerFactory().getMarshaller(samlResponse).marshall(samlResponse);
                }
            }
            return elem;
        } catch (Exception anyE) {
            throw new RuntimeException("Error creating SAML2 XML payload", anyE);
        }
    }
}
