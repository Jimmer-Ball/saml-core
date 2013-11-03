package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.configuration.ConfigurationProperties;
import com.timepoorprogrammer.saml.configuration.ConsumerRedirectionConfiguration;
import com.timepoorprogrammer.saml.configuration.EntityTranslation;
import com.timepoorprogrammer.saml.core.InboundSAML11Message;
import com.timepoorprogrammer.saml.impls.standard.consumer.processor.SAML11AssertionConsumerProcessorImpl;
import com.timepoorprogrammer.saml.configuration.ConsumerRedirectionConfiguration;
import com.timepoorprogrammer.saml.configuration.EntityTranslation;
import com.timepoorprogrammer.saml.core.InboundSAML11Message;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.provider.MetadataProvider;

import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

/**
 * Simplified encapsulation of a SAML11 assertion consumer for use by any of our applications that will use
 * a default SAML11AssertionConsumerProcessor.
 * <p/>
 * If you want to do more complicated things you may need to write a bespoke implementation that meets the rules
 * outlined in the SAML11AssertionConsumerProcessorFactory.
 *
 * @author Jim Ball
 */
public class SAML11AssertionConsumer {
    private ConfigurationProperties configurationProperties;
    private EntityTranslation entityTranslation;
    private MetaDataHandler mdHandler;
    private MetadataProvider mdProvider;
    private String serviceCode;

    /**
     * Setup an assertion consumer from file paths
     *
     * @param serviceCode                 service code
     * @param configurationPropertiesPath Path to SAML configuration file See saml.properties. In this the paths to the
     *                                    SAML metadata and encryption files live
     * @param entityTranslationPropertiesPath
     *                                    Path to translation file for going from serviceCode to public SAML entity
     *                                    identifier and back again. See samlentitytranslation.properties.
     * @param metaDataPath                Path to SAML metadata
     */
    public SAML11AssertionConsumer(final String serviceCode,
                                   final String configurationPropertiesPath,
                                   final String entityTranslationPropertiesPath,
                                   final String metaDataPath) {
        if (serviceCode == null || configurationPropertiesPath == null || entityTranslationPropertiesPath == null || metaDataPath == null) {
            throw new IllegalArgumentException("Missing one or more of service code, properties, or metadata");
        }
        configurationProperties = new ConfigurationProperties(configurationPropertiesPath);
        this.serviceCode = serviceCode;
        entityTranslation = new EntityTranslation(entityTranslationPropertiesPath);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        mdProvider = mdHandler.getMetadata(metaDataPath);
    }

    /**
     * Setup an assertion consumer from URLs
     *
     * @param serviceCode                    service code
     * @param configurationPropertiesURL     URL to SAML configuration file See saml.properties. In this the paths to the
     *                                       SAML metadata and encryption files live
     * @param entityTranslationPropertiesURL URL to translation file for going from serviceCode to public SAML entity
     *                                       identifier and back again. See samlentitytranslation.properties.
     * @param metaDataURL                    URL to SAML metadata
     */
    public SAML11AssertionConsumer(final String serviceCode,
                                   final URL configurationPropertiesURL,
                                   final URL entityTranslationPropertiesURL,
                                   final URL metaDataURL) {
        if (serviceCode == null || configurationPropertiesURL == null || entityTranslationPropertiesURL == null || metaDataURL == null) {
            throw new IllegalArgumentException("Missing one or more of service code, properties, or metadata");
        }
        configurationProperties = new ConfigurationProperties(configurationPropertiesURL);
        this.serviceCode = serviceCode;
        entityTranslation = new EntityTranslation(entityTranslationPropertiesURL);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        mdProvider = mdHandler.getMetadata(metaDataURL);
    }

    /**
     * Setup an assertion consumer from streams
     *
     * @param serviceCode                   service code
     * @param configurationPropertiesStream Stream to SAML configuration file See saml.properties. In this the paths to the
     *                                      SAML metadata and encryption files live
     * @param entityTranslationPropertiesStream
     *                                      Stream to translation file for going from serviceCode to public SAML entity
     *                                      identifier and back again. See samlentitytranslation.properties.
     * @param metaDataStream                Stream to SAML metadata
     */
    public SAML11AssertionConsumer(final String serviceCode,
                                   InputStream configurationPropertiesStream,
                                   InputStream entityTranslationPropertiesStream,
                                   InputStream metaDataStream) {
        if (serviceCode == null || configurationPropertiesStream == null || entityTranslationPropertiesStream == null || metaDataStream == null) {
            throw new IllegalArgumentException("Missing SAML2 handler, service code, and properties and metadata");
        }
        configurationProperties = new ConfigurationProperties(configurationPropertiesStream);
        this.serviceCode = serviceCode;
        entityTranslation = new EntityTranslation(entityTranslationPropertiesStream);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        mdProvider = mdHandler.getMetadata(metaDataStream);
    }

    /**
     * Setup an assertion consumer from properties
     *
     * @param serviceCode                 service code
     * @param configProperties            SAML configuration properties See saml.properties. In this the paths to the
     *                                    SAML metadata and encryption files live
     * @param entityTranslationProperties Translation properties for going from serviceCode to public SAML entity
     *                                    identifier and back again. See samlentitytranslation.properties.
     * @param metaDataStream              Stream to SAML metadata
     */
    public SAML11AssertionConsumer(final String serviceCode,
                                   final Properties configProperties,
                                   final Properties entityTranslationProperties,
                                   InputStream metaDataStream) {
        if (serviceCode == null || configProperties == null || entityTranslationProperties == null || metaDataStream == null) {
            throw new IllegalArgumentException("Missing SAML2 handler, service code, and properties and metadata");
        }
        configurationProperties = new ConfigurationProperties(configProperties);
        this.serviceCode = serviceCode;
        entityTranslation = new EntityTranslation(entityTranslationProperties);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        mdProvider = mdHandler.getMetadata(metaDataStream);
    }

    /**
     * Get inbound SAML11 message details from the context provided
     *
     * @param context context from which the inbound SAML11 message can be obtained
     * @return Inbound SAML11 message
     */
    public InboundSAML11Message getMessageDetails(final SAMLMessageContext context) {
        return new InboundSAML11Message(context);
    }

    /**
     * Given the input issuer, return the right processor details
     *
     * @param issuer issuer details
     * @return vanilla SAML11 processor
     */
    public SAML11AssertionConsumerProcessor getProcessor(final String issuer) {
        if (issuer == null) {
            throw new IllegalArgumentException("Cannot provide a processor without issuer details");
        }
        final String customerCode = entityTranslation.lookupInternalCodeUsingEntityIdentifier(issuer);
        return new SAML11AssertionConsumerProcessorImpl(mdProvider, issuer, customerCode,
                SAMLConstants.SAML11P_NS, serviceCode, mdHandler);
    }

    /**
     * Given the input issuer return details of the redirection configuration we need to redirect to the
     * right customer specific instance of the target service (e.g. MyView).
     *
     * @param issuer issuer
     * @return redirection configuration to allow us to redirect to the right customer specific instance of a target service
     */
    public ConsumerRedirectionConfiguration getRedirectConfig(final String issuer) {
        if (issuer == null) {
            throw new IllegalArgumentException("Cannot provide redirect configuration without issuer details");
        }
        final String customerCode = entityTranslation.lookupInternalCodeUsingEntityIdentifier(issuer);
        return new ConsumerRedirectionConfiguration(configurationProperties, customerCode, serviceCode);
    }
}
