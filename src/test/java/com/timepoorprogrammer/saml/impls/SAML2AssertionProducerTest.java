package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.common.utilities.xml.XMLUtilities;
import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.configuration.ProducerConfiguration;
import com.timepoorprogrammer.saml.core.SAML2Handler;
import com.timepoorprogrammer.saml.impls.SAML2AssertionProducer;
import com.timepoorprogrammer.saml.impls.SAML2AssertionProducerProcessor;
import org.junit.Assert;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import java.io.File;
import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;


/**
 * Test class for the SAML2 assertion producer
 *
 * @author Jim Ball
 */
public class SAML2AssertionProducerTest {
    private static final Logger log = LoggerFactory.getLogger(SAML2AssertionProducerTest.class);
    /**
     * Default setting for producerCustomerCode. Namely, from a SAML metadata point of view, who am I?
     */
    private static final String PRODUCER = "idp_saml2";

    /**
     * The name of the service we create an asertion for
     */
    private static final String SERVICE = "MyView";

    /**
     * Path to overall SAML properties file used by the assertion producer
     */
    private static final String PROPERTIES_FILE = TestHelper.getFullPath("^.*fixtures\\\\configuration\\\\saml.properties$");

    /**
     * Path to Pproperties file holding lookup details between SAML Issuer details and our Northgate internal
     * customer code.
     */
    private static final String ENTITY_TRANSLATION_FILE = TestHelper.getFullPath("^.*fixtures\\\\configuration\\\\samlentitytranslation.properties$");

    /**
     * Path to SAML metadata file describing producers and consumers of assertions
     */
    private static final String META_DATA_FILE = TestHelper.getFullPath("^.*fixtures\\\\metadata\\\\idp_and_sp_metadata.xml$");

    /**
     * Path to key file holding the private key needed to do digital signatures
     */
    private static final String PRIVATE_KEY_FILE = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\clientKeyStore.jks$");

    /**
     * To test a processor requires an initialised SAML library which means an initialed handler
     */
    private static final SAML2Handler HANDLER = new SAML2Handler();

    /**
     * XML utilities
     */
    private static XMLUtilities xmlUtils = new XMLUtilities();

    /**
     * Test getting SAML payload to send
     */
    @Test
    public void testGetSAMLResponsePayload() {
        try {
            // Construct the producer
            SAML2AssertionProducer producer =
                    new SAML2AssertionProducer(PRODUCER, SERVICE, HANDLER, PROPERTIES_FILE, ENTITY_TRANSLATION_FILE, META_DATA_FILE, PRIVATE_KEY_FILE);

            // Check the producer configuration is right given the set of files provided
            ProducerConfiguration config = producer.getProducerConfiguration();
            assertThat(config.getKeyStorePassword(), is("rmi+ssl"));
            assertThat(config.getSigningKeyAlias(), is("localclient"));
            assertThat(config.getSigningKeyPassword(), is("localclient"));
            assertThat(config.getProducerCode(), is(PRODUCER));

            // Create a simple unencrypted assertion
            final SAML2AssertionProducerProcessor processor = producer.getProcessor();
            final Assertion assertion = processor.createAuthnAssertion(HANDLER, "dave");
            assertThat(assertion.getIssuer().getValue(), is(PRODUCER));

            // Create a full payload
            final String encodedSAMLResponse = producer.getSAMLResponsePayload("189502");
            Assert.assertNotNull(encodedSAMLResponse);
            log.info("Encoded signed payload holding encrypted assertion looks like:");
            log.info("\n" + encodedSAMLResponse);
        } catch (Exception anyE) {
            Assert.fail("Error running processor factory main scenario test " + anyE.getMessage());
        }
    }

    /**
     * Test getting SAML payload to send using stream input
     */
    @Test
    public void testGetSAMLResponsePayload_asStreams() {
        try {
            FileInputStream propsStream = new FileInputStream(new File(PROPERTIES_FILE));
            FileInputStream entityTranslationStream = new FileInputStream(new File(ENTITY_TRANSLATION_FILE));
            FileInputStream metadataStream = new FileInputStream(new File(META_DATA_FILE));
            FileInputStream privateKeyStream = new FileInputStream(new File(PRIVATE_KEY_FILE));

            // Construct the producer
            SAML2AssertionProducer producer =
                    new SAML2AssertionProducer(PRODUCER, SERVICE, HANDLER, propsStream, entityTranslationStream, metadataStream, privateKeyStream);

            // Check the producer configuration is right given the set of files provided
            ProducerConfiguration config = producer.getProducerConfiguration();
            assertThat(config.getKeyStorePassword(), is("rmi+ssl"));
            assertThat(config.getSigningKeyAlias(), is("localclient"));
            assertThat(config.getSigningKeyPassword(), is("localclient"));
            assertThat(config.getProducerCode(), is(PRODUCER));

            // Create a simple unencrypted assertion
            final SAML2AssertionProducerProcessor processor = producer.getProcessor();
            final Assertion assertion = processor.createAuthnAssertion(HANDLER, "dave");
            assertThat(assertion.getIssuer().getValue(), is(PRODUCER));

            // Create a full payload
            final String encodedSAMLResponse = producer.getSAMLResponsePayload("189502");
            Assert.assertNotNull(encodedSAMLResponse);
            log.info("Encoded signed payload holding encrypted assertion looks like:");
            log.info("\n" + encodedSAMLResponse);
        } catch (Exception anyE) {
            Assert.fail("Error running processor factory main scenario test " + anyE.getMessage());
        }
    }


    /**
     * Test getting SAML payload to send
     */
    @Test
    public void testGetSAMLResponsePayload_SignAndEncrypt() {
        try {
            // Construct the producer
            SAML2AssertionProducer producer =
                    new SAML2AssertionProducer(PRODUCER, SERVICE, HANDLER, PROPERTIES_FILE, ENTITY_TRANSLATION_FILE, META_DATA_FILE, PRIVATE_KEY_FILE);

            // Check the producer configuration is right given the set of files provided
            ProducerConfiguration config = producer.getProducerConfiguration();
            assertThat(config.getKeyStorePassword(), is("rmi+ssl"));
            assertThat(config.getSigningKeyAlias(), is("localclient"));
            assertThat(config.getSigningKeyPassword(), is("localclient"));
            assertThat(config.getProducerCode(), is(PRODUCER));

            // Create the basic payload seeing it is signed and encrypted
            final Element SAMLResponse = producer.getSAMLResponseAsXML("189502", null);
            log.info("Signed payload holding encrypted assertion looks like:");
            log.info("\n" + xmlUtils.print(SAMLResponse, true));
        } catch (Exception anyE) {
            Assert.fail("Error running processor factory main scenario test " + anyE.getMessage());
        }
    }

    /**
     * Test getting the SAML payload to send, with no signing or encryption
     */
    @Test
    public void testGetSAMLResponseAsXML_NoSigningOrEncryption() {
        try {
            // Construct the producer without any details of any keys as we aren't using them
            SAML2AssertionProducer producer =
                    new SAML2AssertionProducer("SimplestProducer", "SimplestService", HANDLER, PROPERTIES_FILE,
                            ENTITY_TRANSLATION_FILE, META_DATA_FILE, null);

            // Check the producer configuration is right given the set of files provided
            ProducerConfiguration config = producer.getProducerConfiguration();
            Assert.assertNull(config.getKeyStorePassword());
            Assert.assertNull(config.getSigningKeyAlias());
            Assert.assertNull(config.getSigningKeyPassword());
            assertThat(config.getProducerCode(), is("SimplestProducer"));

            // Create the basic payload and see that its both signed and encrypted
            final Element SAMLResponse = producer.getSAMLResponseAsXML("189502", null);
            log.info("Unsigned payload holding unencrypted assertion looks like:");
            log.info("\n" + xmlUtils.print(SAMLResponse, true));
        } catch (Exception anyE) {
            Assert.fail("Error running processor factory main scenario test " + anyE.getMessage());
        }
    }

    /**
     * Test getting the SAML payload to send, with no signing or encryption.  We are trying to break it all here, as
     * passing in a key file path could mess it up.  But actually, it doesn't, as the library uses the settings in
     * the saml.properties file to drive it, doesn't matter whether a key file gets passed in or not.
     */
    @Test
    public void testGetSAMLResponseAsXML_NoSigningOrEncryptionIgnoresPrivateKeyFileAndUsesMetadataOnly() {
        try {
            // Construct the producer without any details of any keys as we aren't using them
            SAML2AssertionProducer producer =
                    new SAML2AssertionProducer("SimplestProducer", "SimplestService", HANDLER, PROPERTIES_FILE,
                            ENTITY_TRANSLATION_FILE, META_DATA_FILE, PRIVATE_KEY_FILE);

            // Check the producer configuration is right given the set of files provided
            ProducerConfiguration config = producer.getProducerConfiguration();
            Assert.assertNull(config.getKeyStorePassword());
            Assert.assertNull(config.getSigningKeyAlias());
            Assert.assertNull(config.getSigningKeyPassword());
            assertThat(config.getProducerCode(), is("SimplestProducer"));

            // Create the basic payload and see that its both signed and encrypted
            final Element SAMLResponse = producer.getSAMLResponseAsXML("189502", null);
            log.info("Unsigned payload holding unencrypted assertion which ignored the keyfile provided looks like:");
            log.info("\n" + xmlUtils.print(SAMLResponse, true));
        } catch (Exception anyE) {
            Assert.fail("Error running processor factory main scenario test " + anyE.getMessage());
        }
    }

    /**
     * Test getting the SAML payload to send, with signing only
     */
    @Test
    public void testGetSAMLResponseAsXML_SigningOnly() {
        try {
            // Construct the producer without any details of any keys as we aren't using them
            SAML2AssertionProducer producer =
                    new SAML2AssertionProducer(PRODUCER, "SimplestService", HANDLER, PROPERTIES_FILE,
                            ENTITY_TRANSLATION_FILE, META_DATA_FILE, PRIVATE_KEY_FILE);

            // Check the producer configuration is right given the set of files provided
            ProducerConfiguration config = producer.getProducerConfiguration();
            assertThat(config.getKeyStorePassword(), is("rmi+ssl"));
            assertThat(config.getSigningKeyAlias(), is("localclient"));
            assertThat(config.getSigningKeyPassword(), is("localclient"));
            assertThat(config.getProducerCode(), is(PRODUCER));

            // Create the basic payload and see that the response is signed
            final Element SAMLResponse = producer.getSAMLResponseAsXML("189502", null);
            log.info("Signed payload holding unencrypted assertion looks like:");
            log.info("\n" + xmlUtils.print(SAMLResponse, true));
        } catch (Exception anyE) {
            Assert.fail("Error running processor factory main scenario test " + anyE.getMessage());
        }
    }

    /**
     * Test getting the SAML payload to send, with encryption only
     */
    @Test
    public void testGetSAMLResponseAsXML_EncryptionOnly() {
        try {
            // Construct the producer without any details of any keys as we aren't using them
            SAML2AssertionProducer producer =
                    new SAML2AssertionProducer("SimplestProducer", "MyView", HANDLER, PROPERTIES_FILE,
                            ENTITY_TRANSLATION_FILE, META_DATA_FILE, PRIVATE_KEY_FILE);

            // Check the producer configuration is right given the set of files provided
            ProducerConfiguration config = producer.getProducerConfiguration();
            Assert.assertNull(config.getKeyStorePassword());
            Assert.assertNull(config.getSigningKeyAlias());
            Assert.assertNull(config.getSigningKeyPassword());
            assertThat(config.getProducerCode(), is("SimplestProducer"));

            // Create the basic payload and see that the assertion is encrypted
            final Element SAMLResponse = producer.getSAMLResponseAsXML("189502", null);
            log.info("Unsigned payload holding encrypted assertion looks like:");
            log.info("\n" + xmlUtils.print(SAMLResponse, true));
        } catch (Exception anyE) {
            Assert.fail("Error running processor factory main scenario test " + anyE.getMessage());
        }
    }

    /**
     * Test getting the SAML payload to send, with no signing or encryption
     */
    @Test
    public void testGetSAMLResponseAsXML_NoSigningOrEncryptionWithAttributes() {
        try {
            // Construct the producer without any details of any keys as we aren't using them
            SAML2AssertionProducer producer =
                    new SAML2AssertionProducer("SimplestProducer", "SimplestService", HANDLER, PROPERTIES_FILE,
                            ENTITY_TRANSLATION_FILE, META_DATA_FILE, null);

            // Check the producer configuration is right given the set of files provided
            ProducerConfiguration config = producer.getProducerConfiguration();
            Assert.assertNull(config.getKeyStorePassword());
            Assert.assertNull(config.getSigningKeyAlias());
            Assert.assertNull(config.getSigningKeyPassword());
            assertThat(config.getProducerCode(), is("SimplestProducer"));

            // Attributes
            Map<String, String> attributes = new HashMap<String, String>(0);
            attributes.put("securityClearance", "C2");
            attributes.put("roles", "editor,reviewer");

            // Create the basic payload and see that its both signed and encrypted
            final Element SAMLResponse = producer.getSAMLResponseAsXML("189502", attributes);
            log.info("Unsigned payload holding unencrypted assertion with attributes looks like:");
            log.info("\n" + xmlUtils.print(SAMLResponse, true));
        } catch (Exception anyE) {
            Assert.fail("Error running processor factory main scenario test " + anyE.getMessage());
        }
    }

    /**
     * Test getting SAML payload to send
     */
    @Test
    public void testGetSAMLResponsePayload_SignAndEncryptWithAttributes() {
        try {
            // Construct the producer
            SAML2AssertionProducer producer =
                    new SAML2AssertionProducer(PRODUCER, SERVICE, HANDLER, PROPERTIES_FILE, ENTITY_TRANSLATION_FILE, META_DATA_FILE, PRIVATE_KEY_FILE);

            // Check the producer configuration is right given the set of files provided
            ProducerConfiguration config = producer.getProducerConfiguration();
            assertThat(config.getKeyStorePassword(), is("rmi+ssl"));
            assertThat(config.getSigningKeyAlias(), is("localclient"));
            assertThat(config.getSigningKeyPassword(), is("localclient"));
            assertThat(config.getProducerCode(), is(PRODUCER));

            // Attributes
            Map<String, String> attributes = new HashMap<String, String>(0);
            attributes.put("securityClearance", "C2");
            attributes.put("roles", "editor,reviewer");

            // Create the basic payload seeing it is signed and encrypted
            final Element SAMLResponse = producer.getSAMLResponseAsXML("189502", attributes);
            log.info("Signed payload holding encrypted assertion with attributes looks like:");
            log.info("\n" + xmlUtils.print(SAMLResponse, true));
        } catch (Exception anyE) {
            Assert.fail("Error running processor factory main scenario test " + anyE.getMessage());
        }
    }

}