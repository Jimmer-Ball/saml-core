package com.timepoorprogrammer.saml.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.URL;
import java.util.Properties;

/**
 * Pickup SAML role configuration properties from file.  See saml.properties for an example
 * of the format.
 *
 * @author Jim Ball
 */
public class ConfigurationProperties implements Serializable {
    private static final long serialVersionUID = 1545723495267379427L;
    private static final Logger log = LoggerFactory.getLogger(ConfigurationProperties.class);
    private Properties config = null;

    public ConfigurationProperties(final Properties properties) {
        this.config = properties;
    }

    /**
     * Open the configuration properties file and read in the properties
     *
     * @param configurationFilePath path to configuration properties file
     */
    public ConfigurationProperties(final String configurationFilePath) {
        if (configurationFilePath == null) {
            throw new IllegalArgumentException("Missing file path");
        }
        InputStream fis = null;
        try {
            config = new Properties();
            fis = new FileInputStream(configurationFilePath);
            config.load(fis);
            log.debug("Loaded properties {} from file {}", config.toString(), configurationFilePath);
        } catch (Exception anyE) {
            final String errorMessage = "Error getting hold of configuration properties from file";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    log.warn("Unable to close configuration properties", e);
                }
            }
        }
    }

    /**
     * Open the configuration resource and read in the properties
     *
     * @param configurationResource configuration resource URL
     */
    public ConfigurationProperties(final URL configurationResource) {
        if (configurationResource == null) {
            throw new IllegalArgumentException("Missing resource");
        }
        try {
            config = new Properties();
            config.load(configurationResource.openStream());
            log.debug("Loaded properties {} from resource {}", config.toString(), configurationResource.getPath());
        } catch (Exception anyE) {
            final String errorMessage = "Error getting hold of configuration properties from resource";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Load properties from stream
     *
     * @param configurationStream configuration properties stream
     */
    public ConfigurationProperties(InputStream configurationStream) {
        if (configurationStream == null) {
            throw new IllegalArgumentException("Missing stream");
        }
        try {
            config = new Properties();
            config.load(configurationStream);
            log.debug("Loaded properties {} from stream", config.toString());
        } catch (Exception anyE) {
            final String errorMessage = "Error getting hold of configuration properties from resource";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Get a parameter from the properties, as taken from Aurora namespacing of properties.
     *
     * @param functArea functional area
     * @param setId     set name
     * @param paramId   parameter name
     * @return value
     */
    public String getParameter(final String functArea, final String setId, final String paramId) {
        return config.getProperty(String.format("%1$s.%2$s.%3$s", functArea, setId, paramId));
    }

    /**
     * The SAML properties "may" hold a value for a producerCustomerCode.  This then gives us a
     * means of validating routes into customer specific installations of Northgate applications
     * dynamically.  So, this method gives the producers bundled with the middleware a means of
     * being dynmaically configured to test a range of back-end routing integration scenarios for
     * different customers without a middleware rebuild.  So the middleware can be used to test
     * ALL routing into customer specific applications as a consequence.
     * <p/>
     * If the setting is found in the configuration file then the producer applies the customer code
     * configured. If the setting isn't found in the configuration file then the producer applies the
     * defaultValue.
     * <p/>
     * It is essential that if you do setup the producerCustomerCode in the configuration file then
     * you already have metadata for an entity that matches the code, and have routing information
     * that matches the code.  See the idp_saml2 set of metadata and configuration for an example
     * of a full set of required metadata and configuration data.
     *
     * @param defaultValue The default value to apply if the setting doesn't exist or is null.
     * @return the testCustomerCode value in the configuration file or null
     *         which can be used as an override on the producers that come with the
     *         middleware.
     */
    public String getProducerCode(final String defaultValue) {
        return config.getProperty("saml.producerCustomerCode", defaultValue);
    }
}
