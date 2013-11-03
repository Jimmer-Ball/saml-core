package com.timepoorprogrammer.saml.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

/**
 * Producer or identity provider configuration used to bind to the right metadata file and to a keystore that
 * holds the private key needed to sign outgoing SAML content.
 * <p/>
 * Please note that a producer may not actually do any digital signing of outgoing content.
 *
 * @author Jim Ball
 */
public class ProducerConfiguration implements Serializable {
    private static final long serialVersionUID = 7246127411192919708L;
    private static final Logger log = LoggerFactory.getLogger(ProducerConfiguration.class);
    private String producerCode;
    private String metadataFileName;
    private String keyStoreName;
    private String keyStorePassword;
    private String signingKeyAlias;
    private String signingKeyPassword;

    /**
     * Get all the properties of a producer and throw if any of them are missing
     *
     * @param properties   properties
     * @param internalCode internal code for the producer
     */
    public ProducerConfiguration(final ConfigurationProperties properties, final String internalCode) {
        if (properties == null || internalCode == null) {
            throw new IllegalArgumentException("Configuration properties and/or producer id missing");
        }
        producerCode = internalCode;
        metadataFileName = properties.getParameter("saml", internalCode, "metadataFileName");
        keyStoreName = properties.getParameter("saml", internalCode, "keyStoreName");
        keyStorePassword = properties.getParameter("saml", internalCode, "keyStorePassword");
        signingKeyAlias = properties.getParameter("saml", internalCode, "signingKeyAlias");
        signingKeyPassword = properties.getParameter("saml", internalCode, "signingKeyPassword");
        if (metadataFileName == null) {
            final String errorMessage = "We don't know where to look for our SAML metadata, check your setup for all the parameters needed to define a producer";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * Have we got all the setting we need to digitally sign an outgoing SAML response or not.
     *
     * @return true if we have everything we need to digitally sign a SAML response, false otherwise
     */
    public boolean signingSettingsProvided() {
        return keyStoreName != null && keyStorePassword != null && signingKeyAlias != null && signingKeyPassword != null;
    }

    public String getProducerCode() {
        return producerCode;
    }

    public void setProducerCode(String producerCode) {
        this.producerCode = producerCode;
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

    public String getSigningKeyAlias() {
        return signingKeyAlias;
    }

    public void setSigningKeyAlias(String signingKeyAlias) {
        this.signingKeyAlias = signingKeyAlias;
    }

    public String getSigningKeyPassword() {
        return signingKeyPassword;
    }

    public void setSigningKeyPassword(String signingKeyPassword) {
        this.signingKeyPassword = signingKeyPassword;
    }

    public String toString() {
        return "ProducerConfiguration{" +
                "producerCode='" + producerCode + '\'' +
                ", metadataFileName='" + metadataFileName + '\'' +
                ", keyStoreName='" + keyStoreName + '\'' +
                ", keyStorePassword='" + keyStorePassword + '\'' +
                ", signingKeyAlias='" + signingKeyAlias + '\'' +
                ", signingKeyPassword='" + signingKeyPassword + '\'' +
                '}';
    }
}
