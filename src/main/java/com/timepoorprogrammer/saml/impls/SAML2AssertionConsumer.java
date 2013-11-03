package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.common.CopyInputStream;
import com.timepoorprogrammer.saml.configuration.ConfigurationProperties;
import com.timepoorprogrammer.saml.configuration.ConsumerConfiguration;
import com.timepoorprogrammer.saml.configuration.ConsumerRedirectionConfiguration;
import com.timepoorprogrammer.saml.configuration.EntityTranslation;
import com.timepoorprogrammer.saml.core.InboundSAML2Message;
import com.timepoorprogrammer.saml.impls.standard.consumer.processor.SAML2AssertionConsumerProcessorImpl;
import com.timepoorprogrammer.saml.common.CopyInputStream;
import com.timepoorprogrammer.saml.core.InboundSAML2Message;
import com.timepoorprogrammer.saml.impls.standard.consumer.processor.SAML2AssertionConsumerProcessorImpl;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.provider.MetadataProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

/**
 * Simplified encapsulation of a SAML2 assertion consumer for use by any of our applications that will use
 * a default SAML2AssertionConsumerProcessor.
 * <p/>
 * If you want to do more complicated things you may need to write a bespoke implementation that meets the rules
 * outlined in the SAML2AssertionConsumerProcessorFactory.
 *
 * @author Jim Ball
 */
public class SAML2AssertionConsumer {
    private ConfigurationProperties configurationProperties;
    private ConsumerConfiguration config;
    private EntityTranslation entityTranslation;
    private MetaDataHandler mdHandler;
    private MetadataProvider mdProvider;
    private String serviceCode;
    private CopyInputStream keyStoreStreamCopy;

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
     * @param privateKeyStorePath         Path to private key store used for decryption may be null if
     *                                    no decryption is to be done
     */
    public SAML2AssertionConsumer(final String serviceCode,
                                  final String configurationPropertiesPath,
                                  final String entityTranslationPropertiesPath,
                                  final String metaDataPath,
                                  final String privateKeyStorePath) {
        if (serviceCode == null || configurationPropertiesPath == null || entityTranslationPropertiesPath == null || metaDataPath == null) {
            throw new IllegalArgumentException("Missing one or more of service code, properties, or metadata");
        }
        this.serviceCode = serviceCode;
        configurationProperties = new ConfigurationProperties(configurationPropertiesPath);
        config = new ConsumerConfiguration(configurationProperties, this.serviceCode);
        entityTranslation = new EntityTranslation(entityTranslationPropertiesPath);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        mdProvider = mdHandler.getMetadata(metaDataPath);
        if (privateKeyStorePath != null) {
            try {
                keyStoreStreamCopy = new CopyInputStream(new FileInputStream(new File(privateKeyStorePath)));
            } catch (Exception anyE) {
                throw new RuntimeException("Cannot find the keystore at " + privateKeyStorePath);
            }
        }
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
     * @param privateKeyStoreURL             URL to private key store used for decryption may be null if no decryption is to be done
     */
    public SAML2AssertionConsumer(final String serviceCode,
                                  final URL configurationPropertiesURL,
                                  final URL entityTranslationPropertiesURL,
                                  final URL metaDataURL,
                                  final URL privateKeyStoreURL) {
        if (serviceCode == null || configurationPropertiesURL == null || entityTranslationPropertiesURL == null || metaDataURL == null) {
            throw new IllegalArgumentException("Missing one or more of service code, properties, or metadata");
        }
        this.serviceCode = serviceCode;
        configurationProperties = new ConfigurationProperties(configurationPropertiesURL);
        config = new ConsumerConfiguration(configurationProperties, this.serviceCode);
        entityTranslation = new EntityTranslation(entityTranslationPropertiesURL);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        mdProvider = mdHandler.getMetadata(metaDataURL);
        if (privateKeyStoreURL != null) {
            try {
                keyStoreStreamCopy = new CopyInputStream(privateKeyStoreURL.openStream());
            } catch (Exception anyE) {
                throw new RuntimeException("Cannot find the keystore at " + privateKeyStoreURL.toString());
            }
        }
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
     * @param privateKeyStoreStream         Stream to private key store used for decryption may be null if no decryption is to be done
     */
    public SAML2AssertionConsumer(final String serviceCode,
                                  InputStream configurationPropertiesStream,
                                  InputStream entityTranslationPropertiesStream,
                                  InputStream metaDataStream,
                                  InputStream privateKeyStoreStream) {
        if (serviceCode == null || configurationPropertiesStream == null || entityTranslationPropertiesStream == null || metaDataStream == null) {
            throw new IllegalArgumentException("Missing one or more of service code, properties, or metadata");
        }
        this.serviceCode = serviceCode;
        configurationProperties = new ConfigurationProperties(configurationPropertiesStream);
        config = new ConsumerConfiguration(configurationProperties, this.serviceCode);
        entityTranslation = new EntityTranslation(entityTranslationPropertiesStream);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        mdProvider = mdHandler.getMetadata(metaDataStream);
        keyStoreStreamCopy = new CopyInputStream(privateKeyStoreStream);
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
     * @param privateKeyStoreStream       Stream to private key store used for decryption may be null if no decryption is to be done
     */
    public SAML2AssertionConsumer(final String serviceCode,
                                  final Properties configProperties,
                                  final Properties entityTranslationProperties,
                                  InputStream metaDataStream,
                                  InputStream privateKeyStoreStream) {
        if (serviceCode == null || configProperties == null || entityTranslationProperties == null || metaDataStream == null) {
            throw new IllegalArgumentException("Missing SAML2 handler, service code, and properties and metadata");
        }
        this.serviceCode = serviceCode;
        configurationProperties = new ConfigurationProperties(configProperties);
        config = new ConsumerConfiguration(configurationProperties, this.serviceCode);
        entityTranslation = new EntityTranslation(entityTranslationProperties);
        mdHandler = MetaDataHandlerFactory.getInstance(null);
        mdProvider = mdHandler.getMetadata(metaDataStream);
        keyStoreStreamCopy = new CopyInputStream(privateKeyStoreStream);
    }

    /**
     * Get inbound SAML2 message details from the context provided
     *
     * @param context context from which the inbound SAML2 message can be obtained
     * @return Inbound SAML2 message
     */
    public InboundSAML2Message getMessageDetails(final SAMLMessageContext context) {
        return new InboundSAML2Message(context);
    }

    /**
     * Given the input issuer, return the appropriate processor details
     *
     * @param issuer issuer details
     * @return vanilla SAML2 processor
     */
    public SAML2AssertionConsumerProcessor getProcessor(final String issuer) {
        if (issuer == null) {
            throw new IllegalArgumentException("Cannot provide a processor without issuer details");
        }
        final String customerCode = entityTranslation.lookupInternalCodeUsingEntityIdentifier(issuer);
        // Given the keystore is presented as a stream, to avoid an end of stream fiasco when
        // an assertion consumer is constructed once, but is used repeatedly to obtain different
        // processors depending on the issuer, then take a copy of the keystore stream each time
        // we build a new consumer
        return new SAML2AssertionConsumerProcessorImpl(mdProvider, issuer, customerCode,
                SAMLConstants.SAML20P_NS, serviceCode, mdHandler, keyStoreStreamCopy.getCopy(),
                config.getKeyStorePassword(), config.getDecryptionKeyAlias(),
                config.getDecryptionKeyPassword());
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
