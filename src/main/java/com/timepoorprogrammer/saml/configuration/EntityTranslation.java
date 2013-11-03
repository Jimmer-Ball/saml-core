package com.timepoorprogrammer.saml.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Translate between a SAML entity identifier and an internal customer/service/partner code, and vice-versa.
 * <p/>
 * For many issuers (identity providers) the issuer details will arrive at the SAML middleware in entity
 * format (urn:oasis:names:SAML:2.0:nameid-format:entity). This means the issuer details look like a URL,
 * for example:  http://idp.example.org.
 * <p/>
 * Using the entity identifier is fine when looking up metadata in our shared trust arrangement that tells us how
 * to decrypt and how to check digital signatures, but is no good when we want to get at the right routing
 * configuration for requests out the back of the middleware and on into the applications (like MyView).
 * <p/>
 * Same goes for when we send SAML out to other service providers.  It may well be they can't cope with getting
 * a request from us with an entity identifier which happens to be the internal Northgate identifier for a given
 * service (say WebView), and instead want/need us to provide a full SAML entity identifier in URL format as
 * they are using inflexible third party kit for their assertion consumer service(s).
 * <p/>
 * We organise our back-end routing (as defined in saml.properties), our deployments, our hosting network
 * architectures, and our bespoke code in downstream applications (e.g. MyView) using the internal customer/partner
 * codes in use within Northgate, and not some SAML issuer URL.  The issuer URL is SAML specific, but the internal
 * customer code gets everywhere in Northgate architecture and application code, and is not limited to SAML
 * interactions.
 * <p/>
 * So we need to be able to swap back and forth between the two forms.  We need to lookup SAML metadata using the
 * SAML entity identifier form expressed as an issuer URL and yet also do back-end routing and engage bespoke code
 * using the internal customer/partner code.
 * <p/>
 * Consequently we may well need to translate back-and-forth between an internal customer/product/partner code and a
 * SAML entity identifier without having to stop the middleware.
 *
 * @author Jim Ball
 */
public class EntityTranslation implements Serializable {
    private static final long serialVersionUID = 5380027369486705852L;
    private static final Logger log = LoggerFactory.getLogger(EntityTranslation.class);
    private Map<String, String> entityMapping = new HashMap<String, String>(0);
    private Properties properties;

    /**
     * Construct entity translation service from properties provided
     *
     * @param properties properties
     */
    public EntityTranslation(final Properties properties) {
        if (properties == null) {
            throw new IllegalArgumentException("Missing required properties");
        }
        this.properties = properties;
        entityMapping = inverseTheMapping(properties);
    }

    /**
     * Open the entity translation properties file and read in the properties, and then
     * inverse the mapping that is found so we can also use the SAML entity identifier
     * to do an inverse lookup of the customer code.
     *
     * @param entityTranslationFilePath path to entity translation properties file
     */
    public EntityTranslation(final String entityTranslationFilePath) {
        if (entityTranslationFilePath == null) {
            throw new IllegalArgumentException("Missing file path required");
        }
        InputStream fis = null;
        try {
            properties = new Properties();
            fis = new FileInputStream(entityTranslationFilePath);
            properties.load(fis);
            log.debug("Loaded SAML entity translations {} from file {}", properties.toString(), entityTranslationFilePath);
            entityMapping = inverseTheMapping(properties);
        } catch (Exception anyE) {
            final String errorMessage = "Error getting hold of SAML entity translation properties";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    log.warn("Unable to close SAML entity translation properties", e);
                }
            }
        }
    }

    /**
     * Open the entity translation resource and read in the properties
     *
     * @param entityTranslationResource entity translation resource URL
     */
    public EntityTranslation(final URL entityTranslationResource) {
        if (entityTranslationResource == null) {
            throw new IllegalArgumentException("Missing resource required");
        }
        try {
            properties = new Properties();
            properties.load(entityTranslationResource.openStream());
            log.debug("Loaded SAML entity translation {} from resource {}", properties.toString(), entityTranslationResource.getPath());
            entityMapping = inverseTheMapping(properties);
        } catch (Exception anyE) {
            final String errorMessage = "Error getting hold of SAML entity translation properties from resource";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Open the entity translation stream and read in the properties
     *
     * @param entityTranslationStream entity translation resource stream
     */
    public EntityTranslation(InputStream entityTranslationStream) {
        if (entityTranslationStream == null) {
            throw new IllegalArgumentException("Missing stream required");
        }
        try {
            properties = new Properties();
            properties.load(entityTranslationStream);
            log.debug("Loaded SAML entity translation {} from stream", properties.toString());
            entityMapping = inverseTheMapping(properties);
        } catch (Exception anyE) {
            final String errorMessage = "Error getting hold of SAML entity translation properties from resource";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Lookup an internal customer/service/partner code given the input entity identifier, or lookup an internal
     * service code given the input entity identifier.
     * <p/>
     * We may or may not have a customer lookup for inbound SAML.  If the customer is known as TZ and uses an
     * unspecified format for their issuer details in both their metadata and inbound assertions (allowing them to
     * avoid having to provide a URL format string in metadata and assertions) then we can continue to directly
     * reference the issuer details they have already provided to reference the right set of configuration in the
     * routing configuration further downstream.
     * <p/>
     * We may or may not have a service lookup.  If we know our service internally as WebView, and we can happily
     * send assertions to another service provider using the entity identifier (issuer) of WebView, then no
     * translation is required.  But if the service provider needs to know us as
     * https://webview.idp.northgatearinso.com then a translation will be required.
     * <p/>
     * We may or may not have a partner lookup.  If we know we can send assertions to partners who can take a simple
     * unspecified format for the issuer details we send them, then we don't need one, otherwise we do.
     * <p/>
     * If we don't have a translation, we simply return the same string as that provided.  So check the entity
     * identifiers being used in incoming SAML and outgoing SAML to know if you need a translation.
     *
     * @param entityIdentifier entity identifier string details, which if null will cause a RuntimeException.
     * @return The appropriate customer/service/partner code to use, which may or may not be the same as the input
     *         string, depending on whether a translation was found or not.
     */
    public String lookupInternalCodeUsingEntityIdentifier(final String entityIdentifier) {
        if (entityIdentifier == null) {
            throw new IllegalArgumentException("Cannot lookup an internal code with a null entity identifier key");
        }
        String internalCode;
        String foundLookup = entityMapping.get(entityIdentifier);
        if (foundLookup != null) {
            // Set the code to what we find
            internalCode = foundLookup;
            log.debug("Internal code lookup of {} found for entity {}", internalCode, entityIdentifier);
        } else {
            // Set the code to what we already have
            log.debug("No internal code lookup found for entity {}", entityIdentifier);
            internalCode = entityIdentifier;
        }
        return internalCode;
    }

    /**
     * Lookup SAML entity identifier details given the input internal customer code or internal product code.
     * <p/>
     * We may or may not have a customer lookup fro inbound SAML.  If the customer is known as TZ and uses an
     * unspecified format for their issuer details in both their metadata and inbound assertions (allowing them to
     * avoid having to provide a URL format string in metadata and assertions) then we can continue to directly
     * reference the issuer details they have already provided to reference the right set of configuration in the
     * routing configuration further downstream.
     * <p/>
     * We may or may not have a service lookup.  If we know our service internally as WebView, and we can happily
     * send assertions to another service provider using the entity identifier (issuer) of WebView, then no
     * translation is required.  But if some remote service provider needs to know us as as an IDP with a formal
     * SAML entity identifier of https://webview.idp.northgatearinso.com then a translation will be required
     * between the internal code WebView and the URL just provided (for example).
     * <p/>
     * If we don't have a translation, we simply return the same string as that provided.  So check the entity
     * identifiers being used in incoming SAML and outgoing SAML to know if you need a translation.
     *
     * @param internalCode Northgate customer or service code which if null will cause a RuntimeException.
     * @return The appropriate entity identifier to use, which may or may not be the input string, depending on
     *         whether a translation to entity identifier details was found or not.
     */
    public String lookupEntityIdentifierUsingInternalCode(final String internalCode) {
        if (internalCode == null) {
            throw new IllegalArgumentException("Cannot lookup entity identifier with a null internal code key");
        }
        String entityIdentifier;
        String foundLookup = (String) properties.get(internalCode);
        if (foundLookup != null) {
            // Set the entity identifier to what we find
            entityIdentifier = foundLookup;
            log.debug("Entity identifier lookup of {} found for internal code {}", entityIdentifier, internalCode);
        } else {
            // Set the entity identifier to what we already have
            log.debug("No entity identifier lookup found for internal code {}", internalCode);
            entityIdentifier = internalCode;
        }
        return entityIdentifier;
    }

    /**
     * Properties are a bit poor on the string format of what can be a key.  A key needs to be a simple alphanumeric
     * string, whether the properties are in simple text format or in properties XML format.  So in order to do a
     * lookup of the internal code given the entity identifier we have to switch the lookup details around to map
     * the entity identifier (as a key) to the customer code (as a value).
     *
     * @param properties properties
     * @return Map of strings holding the inversed properties mappings
     */
    private Map<String, String> inverseTheMapping(final Properties properties) {
        Map<String, String> mapping = new HashMap<String, String>(0);
        final Set<String> keys = properties.stringPropertyNames();
        for (String key : keys) {
            final String value = (String) properties.get(key);
            mapping.put(value, key);
        }
        return mapping;
    }
}