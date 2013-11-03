package com.timepoorprogrammer.saml.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

/**
 * Private keystore details for a consumer that holds the private key needed to decrypt incoming SAML2 content.
 * The configuration is organised on a per service code basis within the configuration.
 * <p/>
 * Please note that a consumer may not expect any encryption to be done to assertions that arrive at them, so
 * don't actually need to hold a private key used for decryption purposes.
 *
 * @author Jim Ball
 */
public class ConsumerConfiguration implements Serializable {
    private static final long serialVersionUID = 6542151549549855642L;
    private static final Logger log = LoggerFactory.getLogger(ConsumerConfiguration.class);
    private String consumerCode;
    private String metadataFileName;
    private String keyStoreName;
    private String keyStorePassword;
    private String decryptionKeyAlias;
    private String decryptionKeyPassword;

    /**
     * Extract all the required settings for a consumer and throw if any are missing.
     *
     * @param properties   properties
     * @param internalCode service provider internal Northgate customer code
     */
    public ConsumerConfiguration(final ConfigurationProperties properties, final String internalCode) {
        if (properties == null || internalCode == null) {
            throw new IllegalArgumentException("Configuration properties and/or serviceProviderCode missing");
        }
        consumerCode = internalCode;
        metadataFileName = properties.getParameter("saml", internalCode, "metadataFileName");
        keyStoreName = properties.getParameter("saml", internalCode, "keyStoreName");
        keyStorePassword = properties.getParameter("saml", internalCode, "keyStorePassword");
        decryptionKeyAlias = properties.getParameter("saml", internalCode, "decryptionKeyAlias");
        decryptionKeyPassword = properties.getParameter("saml", internalCode, "decryptionKeyPassword");
        if (metadataFileName == null) {
            final String errorMessage = "We don't know where to look for our SAML metadata, check your setup for all the parameters needed to define a producer";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * Have we got all the settings we need to decrypt an incoming assertion with our private key?
     *
     * @return true if we've got all the settings we need to do decryption, false otherwise
     */
    public boolean decryptionSettingsProvided() {
        return keyStoreName != null && keyStorePassword != null && decryptionKeyAlias != null && decryptionKeyPassword != null;
    }

    public String getConsumerCode() {
        return consumerCode;
    }

    public void setConsumerCode(String consumerCode) {
        this.consumerCode = consumerCode;
    }

    public String getMetadataFileName() {
        return metadataFileName;
    }

    public void setMetadataFileName(String metadataFileName) {
        this.metadataFileName = metadataFileName;
    }

    public String getKeyStoreName() {
        return keyStoreName;
    }

    public void setKeyStoreName(String keyStoreName) {
        this.keyStoreName = keyStoreName;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getDecryptionKeyAlias() {
        return decryptionKeyAlias;
    }

    public void setDecryptionKeyAlias(String decryptionKeyAlias) {
        this.decryptionKeyAlias = decryptionKeyAlias;
    }

    public String getDecryptionKeyPassword() {
        return decryptionKeyPassword;
    }

    public void setDecryptionKeyPassword(String decryptionKeyPassword) {
        this.decryptionKeyPassword = decryptionKeyPassword;
    }

    public String toString() {
        return "ConsumerConfiguration{" +
                "consumerCode='" + consumerCode + '\'' +
                ", metadataFileName='" + metadataFileName + '\'' +
                ", keyStoreName='" + keyStoreName + '\'' +
                ", keyStorePassword='" + keyStorePassword + '\'' +
                ", decryptionKeyAlias='" + decryptionKeyAlias + '\'' +
                ", decryptionKeyPassword='" + decryptionKeyPassword + '\'' +
                '}';
    }
}