package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.configuration.ConsumerRedirectionConfiguration;
import com.timepoorprogrammer.saml.core.InboundSAML2Message;
import com.timepoorprogrammer.saml.core.SAML2Handler;
import com.timepoorprogrammer.saml.core.SAMLAssertionValidationResult;
import com.timepoorprogrammer.saml.core.SAMLResponseValidationResult;
import com.timepoorprogrammer.saml.impls.SAML2AssertionConsumer;
import com.timepoorprogrammer.saml.impls.SAML2AssertionConsumerProcessor;
import com.timepoorprogrammer.saml.impls.SAML2AssertionProducer;
import org.junit.Assert;
import org.junit.Test;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;


/**
 * Test class for the SAML2 assertion consumer.  Most of the good ideas here have been borrowed from the Shibboleth test
 * framework examples, e.g. as found at
 * https://svn.shibboleth.net/java-opensaml2/tags/2.2.3/src/test/java/org/opensaml/saml2/binding/decoding/HTTPPostDecoderTest.java
 *
 * @author Jim Ball
 */
public class SAML2AssertionConsumerTest {
    private static final Logger log = LoggerFactory.getLogger(SAML2AssertionConsumerTest.class);
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
    private static final String PRIVATE_DECRYPTION_KEY_FILE = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\serviceKeyStore.jks$");

    /**
     * Path to key file holding the private key needed to do digital signatures
     */
    private static final String PRIVATE_SIGNING_KEY_FILE = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\clientKeyStore.jks$");

    /**
     * To test a processor requires an initialised SAML library which means an initialed handler
     */
    private static final SAML2Handler HANDLER = new SAML2Handler();

    /**
     * Test consuming SAML2 payload using file based configuration
     */
    @Test
    public void testConsumer_FileBasedConfiguration() {
        SAML2AssertionConsumer classUnderTest =
                new SAML2AssertionConsumer("MyView", PROPERTIES_FILE, ENTITY_TRANSLATION_FILE, META_DATA_FILE, PRIVATE_DECRYPTION_KEY_FILE);
        // Test consumption of payload holding encrypted assertion and signed response. So build a HTTP POST from 
        // customer "idp_sam2" to service "MyView" for module "payslips", user "189502", with no extra attributes.
        try {
            SAMLMessageContext context = new BasicSAMLMessageContext();
            context.setInboundMessageTransport(new HttpServletRequestAdapter(
                    buildIncomingHTTPRequest("idp_saml2", "MyView", "payslips", "189502", null)));
            HTTPPostDecoder messageDecoder = new HTTPPostDecoder();
            messageDecoder.decode(context);
            final InboundSAML2Message message = classUnderTest.getMessageDetails(context);
            if (message.hasRequiredDetails()) {
                final String issuer = message.getIssuer();
                final String relayState = message.getRelayState();
                final Response samlResponse = message.getResponse();
                assertThat(issuer, is("idp_saml2"));
                assertThat(relayState, is("payslips"));
                // Get the redirection details we would use to back-door authorise with some service, and 
                // use to determine our service re-direction strategy following successful back-door authorisation
                final ConsumerRedirectionConfiguration redirectConfig = classUnderTest.getRedirectConfig(issuer);
                assertThat(redirectConfig.getServiceCode(), is("MyView"));
                assertThat(redirectConfig.getCustomerCode(), is("idp_saml2"));
                // Use the consumer processor to process the new arrival
                SAML2AssertionConsumerProcessor consumerProcessor = classUnderTest.getProcessor(issuer);
                // Validate the SAML response content
                SAMLResponseValidationResult responseValidationResult = consumerProcessor.validate(samlResponse);
                if (!responseValidationResult.isValid()) {
                    Assert.fail("Response provided has failed validation: " + responseValidationResult.getErrorDetails());
                }
                // Check the signature if the consumer signs the SAML requests it sends
                if (consumerProcessor.idpSignsMessages()) {
                    log.debug("Issuer " + issuer + " signs its SAML content according to our shared metadata, checking signature");
                    if (!consumerProcessor.isSignatureGood(samlResponse.getSignature())) {
                        Assert.fail("The signature is no good when it should be");
                    }
                }
                // Process the assertion contents
                Assertion gotAssertion = null;
                final Decrypter samlDecrypter = consumerProcessor.getDecrypter();
                if (samlDecrypter != null) {
                    // Check the encryption/decryption if the service expects a client to encrypt what it sends out
                    final EncryptedAssertion encryptedAssertion = samlResponse.getEncryptedAssertions().get(0);
                    if (encryptedAssertion != null) {
                        try {
                            gotAssertion = samlDecrypter.decrypt(encryptedAssertion);
                        } catch (Exception anyE) {
                            Assert.fail("Error doing decryption");
                        }
                    } else {
                        Assert.fail("With the target service we were expecting an encrypted assertion");
                    }
                } else {
                    Assert.fail("With the target service we were expecting an encrypted assertion");
                }
                // Validate the contents of the assertion and redirect to the error page if invalid
                SAMLAssertionValidationResult assertionValidationResult = consumerProcessor.validate(gotAssertion, issuer);
                if (!assertionValidationResult.isValid()) {
                    Assert.fail("Assertion provided has failed validation: " + assertionValidationResult.getErrorDetails());
                }
                // Get the identifier of the user we expect
                final String userIdentifier = gotAssertion.getSubject().getNameID().getValue();
                assertThat(userIdentifier, is("189502"));
                // Get any attributes we expected
            } else {
                Assert.fail("Missing the required details needed to processing an incoming SAML2 payload");
            }
        } catch (Exception anyE) {
            Assert.fail("Generic assertion consumer error: " + anyE.getMessage());
        }

        // Test consumption of payload holding encrypted assertion and signed response. So build a HTTP POST from 
        // customer "idp_sam2" to service "MyView" for module "payslips", user "189502", with no extra attributes.
        try {
            SAMLMessageContext context = new BasicSAMLMessageContext();
            Map<String, String> attributes = new HashMap<String, String>(0);
            attributes.put("role", "code monkey");
            attributes.put("expectation", "low to middling");
            context.setInboundMessageTransport(new HttpServletRequestAdapter(
                    buildIncomingHTTPRequest("idp_saml2", "MyView", "payslips", "189502", attributes)));
            HTTPPostDecoder messageDecoder = new HTTPPostDecoder();
            messageDecoder.decode(context);
            final InboundSAML2Message message = classUnderTest.getMessageDetails(context);
            if (message.hasRequiredDetails()) {
                final String issuer = message.getIssuer();
                final String relayState = message.getRelayState();
                final Response samlResponse = message.getResponse();
                assertThat(issuer, is("idp_saml2"));
                assertThat(relayState, is("payslips"));
                // Get the redirection details we would use to back-door authorise with some service, and 
                // use to determine our service re-direction strategy following successful back-door authorisation
                final ConsumerRedirectionConfiguration redirectConfig = classUnderTest.getRedirectConfig(issuer);
                assertThat(redirectConfig.getServiceCode(), is("MyView"));
                assertThat(redirectConfig.getCustomerCode(), is("idp_saml2"));
                // Use the consumer processor to process the new arrival
                SAML2AssertionConsumerProcessor consumerProcessor = classUnderTest.getProcessor(issuer);
                // Validate the SAML response content
                SAMLResponseValidationResult responseValidationResult = consumerProcessor.validate(samlResponse);
                if (!responseValidationResult.isValid()) {
                    Assert.fail("Response provided has failed validation: " + responseValidationResult.getErrorDetails());
                }
                // Check the signature if the consumer signs the SAML requests it sends
                if (consumerProcessor.idpSignsMessages()) {
                    log.debug("Issuer " + issuer + " signs its SAML content according to our shared metadata, checking signature");
                    if (!consumerProcessor.isSignatureGood(samlResponse.getSignature())) {
                        Assert.fail("The signature is no good when it should be");
                    }
                }
                // Process the assertion contents
                Assertion gotAssertion = null;
                final Decrypter samlDecrypter = consumerProcessor.getDecrypter();
                if (samlDecrypter != null) {
                    // Check the encryption/decryption if the service expects a client to encrypt what it sends out
                    final EncryptedAssertion encryptedAssertion = samlResponse.getEncryptedAssertions().get(0);
                    if (encryptedAssertion != null) {
                        try {
                            gotAssertion = samlDecrypter.decrypt(encryptedAssertion);
                        } catch (Exception anyE) {
                            Assert.fail("Error doing decryption");
                        }
                    } else {
                        Assert.fail("With the target service we were expecting an encrypted assertion");
                    }
                } else {
                    Assert.fail("With the target service we were expecting an encrypted assertion");
                }
                // Validate the contents of the assertion and redirect to the error page if invalid
                SAMLAssertionValidationResult assertionValidationResult = consumerProcessor.validate(gotAssertion, issuer);
                if (!assertionValidationResult.isValid()) {
                    Assert.fail("Assertion provided has failed validation: " + assertionValidationResult.getErrorDetails());
                }
                // Get the identifier of the user we expect
                final String userIdentifier = gotAssertion.getSubject().getNameID().getValue();
                assertThat(userIdentifier, is("189502"));
                // Get any attributes we expected
                List<AttributeStatement> attributeStatements = gotAssertion.getAttributeStatements();
                assertThat(attributeStatements, notNullValue());
                assertThat(attributeStatements.size(), is(1));
                final List<Attribute> gotAttributes = attributeStatements.get(0).getAttributes();
                assertThat(gotAttributes.size(), is(2));
                for (Attribute attribute : gotAttributes) {
                    if (attribute.getName().equals("role")) {
                        assertThat(attribute.getDOM().getTextContent(), is("code monkey"));
                    }
                    if (attribute.getName().equals("expectation")) {
                        assertThat(attribute.getDOM().getTextContent(), is("low to middling"));
                    }
                }
            } else {
                Assert.fail("Missing the required details needed to processing an incoming SAML2 payload");
            }
        } catch (Exception anyE) {
            Assert.fail("Generic assertion consumer error: " + anyE.getMessage());
        }


        // Test consumption of payload holding encrypted assertion and signed response. So build a HTTP POST from 
        // customer "idp_sam2" to service "MyView" for the main page, user "189502", with no extra attributes.
        try {
            SAMLMessageContext context = new BasicSAMLMessageContext();
            context.setInboundMessageTransport(new HttpServletRequestAdapter(
                    buildIncomingHTTPRequest("idp_saml2", "MyView", null, "189502", null)));
            HTTPPostDecoder messageDecoder = new HTTPPostDecoder();
            messageDecoder.decode(context);
            final InboundSAML2Message message = classUnderTest.getMessageDetails(context);
            if (message.hasRequiredDetails()) {
                final String issuer = message.getIssuer();
                final String relayState = message.getRelayState();
                final Response samlResponse = message.getResponse();
                assertThat(issuer, is("idp_saml2"));
                // Relay state (or module) wasn't provided so should be null
                Assert.assertNull(relayState);
                // Get the redirection details we would use to back-door authorise with some service, and 
                // use to determine our service re-direction strategy following successful back-door authorisation
                final ConsumerRedirectionConfiguration redirectConfig = classUnderTest.getRedirectConfig(issuer);
                assertThat(redirectConfig.getServiceCode(), is("MyView"));
                assertThat(redirectConfig.getCustomerCode(), is("idp_saml2"));
                // Use the consumer processor to process the new arrival
                SAML2AssertionConsumerProcessor consumerProcessor = classUnderTest.getProcessor(issuer);
                // Validate the SAML response content
                SAMLResponseValidationResult responseValidationResult = consumerProcessor.validate(samlResponse);
                if (!responseValidationResult.isValid()) {
                    Assert.fail("Response provided has failed validation: " + responseValidationResult.getErrorDetails());
                }
                // Check the signature if the consumer signs the SAML requests it sends
                if (consumerProcessor.idpSignsMessages()) {
                    log.debug("Issuer " + issuer + " signs its SAML content according to our shared metadata, checking signature");
                    if (!consumerProcessor.isSignatureGood(samlResponse.getSignature())) {
                        Assert.fail("The signature is no good when it should be");
                    }
                }
                // Process the assertion contents
                Assertion gotAssertion = null;
                final Decrypter samlDecrypter = consumerProcessor.getDecrypter();
                if (samlDecrypter != null) {
                    // Check the encryption/decryption if the service expects a client to encrypt what it sends out
                    final EncryptedAssertion encryptedAssertion = samlResponse.getEncryptedAssertions().get(0);
                    if (encryptedAssertion != null) {
                        try {
                            gotAssertion = samlDecrypter.decrypt(encryptedAssertion);
                        } catch (Exception anyE) {
                            Assert.fail("Error doing decryption");
                        }
                    } else {
                        Assert.fail("With the target service we were expecting an encrypted assertion");
                    }
                } else {
                    Assert.fail("With the target service we were expecting an encrypted assertion");
                }
                // Validate the contents of the assertion and redirect to the error page if invalid
                SAMLAssertionValidationResult assertionValidationResult = consumerProcessor.validate(gotAssertion, issuer);
                if (!assertionValidationResult.isValid()) {
                    Assert.fail("Assertion provided has failed validation: " + assertionValidationResult.getErrorDetails());
                }
                // Get the identifier of the user we expect
                final String userIdentifier = gotAssertion.getSubject().getNameID().getValue();
                assertThat(userIdentifier, is("189502"));
                // Get any attributes we expected
            } else {
                Assert.fail("Missing the required details needed to processing an incoming SAML2 payload");
            }
        } catch (Exception anyE) {
            Assert.fail("Generic assertion consumer error: " + anyE.getMessage());
        }

        // Test consumption of payload holding encrypted assertion and signed response. So build a HTTP POST from
        // customer "idp_sam2" to service "MyView" with a deliberately empty string relayState, user "189502", with
        // no extra attributes.
        try {
            SAMLMessageContext context = new BasicSAMLMessageContext();
            context.setInboundMessageTransport(new HttpServletRequestAdapter(
                    buildIncomingHTTPRequest("idp_saml2", "MyView", "", "189502", null)));
            HTTPPostDecoder messageDecoder = new HTTPPostDecoder();
            messageDecoder.decode(context);
            final InboundSAML2Message message = classUnderTest.getMessageDetails(context);
            if (message.hasRequiredDetails()) {
                final String issuer = message.getIssuer();
                final String relayState = message.getRelayState();
                final Response samlResponse = message.getResponse();
                assertThat(issuer, is("idp_saml2"));
                // Relay state (or module) even if its empty should be reported as null
                Assert.assertNull(relayState);
                // Get the redirection details we would use to back-door authorise with some service, and
                // use to determine our service re-direction strategy following successful back-door authorisation
                final ConsumerRedirectionConfiguration redirectConfig = classUnderTest.getRedirectConfig(issuer);
                assertThat(redirectConfig.getServiceCode(), is("MyView"));
                assertThat(redirectConfig.getCustomerCode(), is("idp_saml2"));
                // Use the consumer processor to process the new arrival
                SAML2AssertionConsumerProcessor consumerProcessor = classUnderTest.getProcessor(issuer);
                // Validate the SAML response content
                SAMLResponseValidationResult responseValidationResult = consumerProcessor.validate(samlResponse);
                if (!responseValidationResult.isValid()) {
                    Assert.fail("Response provided has failed validation: " + responseValidationResult.getErrorDetails());
                }
                // Check the signature if the consumer signs the SAML requests it sends
                if (consumerProcessor.idpSignsMessages()) {
                    log.debug("Issuer " + issuer + " signs its SAML content according to our shared metadata, checking signature");
                    if (!consumerProcessor.isSignatureGood(samlResponse.getSignature())) {
                        Assert.fail("The signature is no good when it should be");
                    }
                }
                // Process the assertion contents
                Assertion gotAssertion = null;
                final Decrypter samlDecrypter = consumerProcessor.getDecrypter();
                if (samlDecrypter != null) {
                    // Check the encryption/decryption if the service expects a client to encrypt what it sends out
                    final EncryptedAssertion encryptedAssertion = samlResponse.getEncryptedAssertions().get(0);
                    if (encryptedAssertion != null) {
                        try {
                            gotAssertion = samlDecrypter.decrypt(encryptedAssertion);
                        } catch (Exception anyE) {
                            Assert.fail("Error doing decryption");
                        }
                    } else {
                        Assert.fail("With the target service we were expecting an encrypted assertion");
                    }
                } else {
                    Assert.fail("With the target service we were expecting an encrypted assertion");
                }
                // Validate the contents of the assertion and redirect to the error page if invalid
                SAMLAssertionValidationResult assertionValidationResult = consumerProcessor.validate(gotAssertion, issuer);
                if (!assertionValidationResult.isValid()) {
                    Assert.fail("Assertion provided has failed validation: " + assertionValidationResult.getErrorDetails());
                }
                // Get the identifier of the user we expect
                final String userIdentifier = gotAssertion.getSubject().getNameID().getValue();
                assertThat(userIdentifier, is("189502"));
                // Get any attributes we expected
            } else {
                Assert.fail("Missing the required details needed to processing an incoming SAML2 payload");
            }
        } catch (Exception anyE) {
            Assert.fail("Generic assertion consumer error: " + anyE.getMessage());
        }

        // Test consumption of payload holding unencrypted assertion and signed response. So build a HTTP POST from
        // customer "idp_sam2" to service "SimpleService" with null relayState, and user "1234", with no extra 
        // attributes.
        classUnderTest =
                new SAML2AssertionConsumer("SimplestService", PROPERTIES_FILE, ENTITY_TRANSLATION_FILE, META_DATA_FILE, PRIVATE_DECRYPTION_KEY_FILE);
        try {
            SAMLMessageContext context = new BasicSAMLMessageContext();
            context.setInboundMessageTransport(new HttpServletRequestAdapter(
                    buildIncomingHTTPRequest("idp_saml2", "SimplestService", null, "1234", null)));
            HTTPPostDecoder messageDecoder = new HTTPPostDecoder();
            messageDecoder.decode(context);
            final InboundSAML2Message message = classUnderTest.getMessageDetails(context);
            if (message.hasRequiredDetails()) {
                final String issuer = message.getIssuer();
                final String relayState = message.getRelayState();
                final Response samlResponse = message.getResponse();
                assertThat(issuer, is("idp_saml2"));
                // Relay state (or module) even if its empty should be reported as null
                Assert.assertNull(relayState);
                // Get the redirection details we would use to back-door authorise with some service, and
                // use to determine our service re-direction strategy following successful back-door authorisation
                final ConsumerRedirectionConfiguration redirectConfig = classUnderTest.getRedirectConfig(issuer);
                assertThat(redirectConfig.getServiceCode(), is("SimplestService"));
                assertThat(redirectConfig.getCustomerCode(), is("idp_saml2"));
                // Use the consumer processor to process the new arrival
                SAML2AssertionConsumerProcessor consumerProcessor = classUnderTest.getProcessor(issuer);
                // Validate the SAML response content
                SAMLResponseValidationResult responseValidationResult = consumerProcessor.validate(samlResponse);
                if (!responseValidationResult.isValid()) {
                    Assert.fail("Response provided has failed validation: " + responseValidationResult.getErrorDetails());
                }
                // Check the signature if the consumer signs the SAML requests it sends
                if (consumerProcessor.idpSignsMessages()) {
                    log.debug("Issuer " + issuer + " signs its SAML content according to our shared metadata, checking signature");
                    if (!consumerProcessor.isSignatureGood(samlResponse.getSignature())) {
                        Assert.fail("The signature is no good when it should be");
                    }
                }
                // Process the assertion contents
                Assertion gotAssertion = null;
                final Decrypter samlDecrypter = consumerProcessor.getDecrypter();
                if (samlDecrypter != null) {
                    Assert.fail("With the simple service we do not expect any encryption");
                } else {
                    gotAssertion = samlResponse.getAssertions().get(0);
                }
                // Validate the contents of the assertion and redirect to the error page if invalid
                SAMLAssertionValidationResult assertionValidationResult = consumerProcessor.validate(gotAssertion, issuer);
                if (!assertionValidationResult.isValid()) {
                    Assert.fail("Assertion provided has failed validation: " + assertionValidationResult.getErrorDetails());
                }
                // Get the identifier of the user we expect
                final String userIdentifier = gotAssertion.getSubject().getNameID().getValue();
                assertThat(userIdentifier, is("1234"));
                // Get any attributes we expected
            } else {
                Assert.fail("Missing the required details needed to processing an incoming SAML2 payload");
            }
        } catch (Exception anyE) {
            Assert.fail("Generic assertion consumer error: " + anyE.getMessage());
        }

        // Test consumption of payload holding unencrypted assertion and unsigned response. So build a HTTP POST from
        // customer "SimplestProducer" to service "SimpleService" with null relayState, and user "345", with no extra 
        // attributes.
        try {
            SAMLMessageContext context = new BasicSAMLMessageContext();
            context.setInboundMessageTransport(new HttpServletRequestAdapter(
                    buildIncomingHTTPRequest("SimplestProducer", "SimplestService", null, "345", null)));
            HTTPPostDecoder messageDecoder = new HTTPPostDecoder();
            messageDecoder.decode(context);
            final InboundSAML2Message message = classUnderTest.getMessageDetails(context);
            if (message.hasRequiredDetails()) {
                final String issuer = message.getIssuer();
                final String relayState = message.getRelayState();
                final Response samlResponse = message.getResponse();
                assertThat(issuer, is("SimplestProducer"));
                // Relay state (or module) even if its empty should be reported as null
                Assert.assertNull(relayState);
                // Get the redirection details we would use to back-door authorise with some service, and
                // use to determine our service re-direction strategy following successful back-door authorisation
                final ConsumerRedirectionConfiguration redirectConfig = classUnderTest.getRedirectConfig(issuer);
                assertThat(redirectConfig.getServiceCode(), is("SimplestService"));
                assertThat(redirectConfig.getCustomerCode(), is("SimplestProducer"));
                // Use the consumer processor to process the new arrival
                SAML2AssertionConsumerProcessor consumerProcessor = classUnderTest.getProcessor(issuer);
                // Validate the SAML response content
                SAMLResponseValidationResult responseValidationResult = consumerProcessor.validate(samlResponse);
                if (!responseValidationResult.isValid()) {
                    Assert.fail("Response provided has failed validation: " + responseValidationResult.getErrorDetails());
                }
                // Check the signature if the consumer signs the SAML requests it sends
                if (consumerProcessor.idpSignsMessages()) {
                    Assert.fail("The SimplestProducer doesn't do digital signatures");
                }
                // Process the assertion contents
                Assertion gotAssertion = null;
                final Decrypter samlDecrypter = consumerProcessor.getDecrypter();
                if (samlDecrypter != null) {
                    Assert.fail("With the simple service we do not expect any encryption");
                } else {
                    gotAssertion = samlResponse.getAssertions().get(0);
                }
                // Validate the contents of the assertion and redirect to the error page if invalid
                SAMLAssertionValidationResult assertionValidationResult = consumerProcessor.validate(gotAssertion, issuer);
                if (!assertionValidationResult.isValid()) {
                    Assert.fail("Assertion provided has failed validation: " + assertionValidationResult.getErrorDetails());
                }
                // Get the identifier of the user we expect
                final String userIdentifier = gotAssertion.getSubject().getNameID().getValue();
                assertThat(userIdentifier, is("345"));
                // Get any attributes we expected
            } else {
                Assert.fail("Missing the required details needed to processing an incoming SAML2 payload");
            }
        } catch (Exception anyE) {
            Assert.fail("Generic assertion consumer error: " + anyE.getMessage());
        }
    }

    /**
     * Test consuming SAML2 payload using stream based configuration
     */
    @Test
    public void testConsumer_StreamBasedConfiguration() {
        FileInputStream propsStream = null;
        FileInputStream entityTranslationStream = null;
        FileInputStream metadataStream = null;
        FileInputStream privateKeyStream = null;
        try {
            propsStream = new FileInputStream(new File(PROPERTIES_FILE));
            entityTranslationStream = new FileInputStream(new File(ENTITY_TRANSLATION_FILE));
            metadataStream = new FileInputStream(new File(META_DATA_FILE));
            privateKeyStream = new FileInputStream(new File(PRIVATE_DECRYPTION_KEY_FILE));
        } catch (Exception anyE) {
            Assert.fail("Error creating streams");
        }

        SAML2AssertionConsumer classUnderTest =
                new SAML2AssertionConsumer("MyView", propsStream, entityTranslationStream, metadataStream, privateKeyStream);
        // Test consumption of payload holding encrypted assertion and signed response. So build a HTTP POST from 
        // customer "idp_sam2" to service "MyView" for module "payslips", user "189502", with no extra attributes.
        try {
            SAMLMessageContext context = new BasicSAMLMessageContext();
            context.setInboundMessageTransport(new HttpServletRequestAdapter(
                    buildIncomingHTTPRequest("idp_saml2", "MyView", "payslips", "189502", null)));
            HTTPPostDecoder messageDecoder = new HTTPPostDecoder();
            messageDecoder.decode(context);
            final InboundSAML2Message message = classUnderTest.getMessageDetails(context);
            if (message.hasRequiredDetails()) {
                final String issuer = message.getIssuer();
                final String relayState = message.getRelayState();
                final Response samlResponse = message.getResponse();
                assertThat(issuer, is("idp_saml2"));
                assertThat(relayState, is("payslips"));
                // Get the redirection details we would use to back-door authorise with some service, and 
                // use to determine our service re-direction strategy following successful back-door authorisation
                final ConsumerRedirectionConfiguration redirectConfig = classUnderTest.getRedirectConfig(issuer);
                assertThat(redirectConfig.getServiceCode(), is("MyView"));
                assertThat(redirectConfig.getCustomerCode(), is("idp_saml2"));
                // Use the consumer processor to process the new arrival
                SAML2AssertionConsumerProcessor consumerProcessor = classUnderTest.getProcessor(issuer);
                // Validate the SAML response content
                SAMLResponseValidationResult responseValidationResult = consumerProcessor.validate(samlResponse);
                if (!responseValidationResult.isValid()) {
                    Assert.fail("Response provided has failed validation: " + responseValidationResult.getErrorDetails());
                }
                // Check the signature if the consumer signs the SAML requests it sends
                if (consumerProcessor.idpSignsMessages()) {
                    log.debug("Issuer " + issuer + " signs its SAML content according to our shared metadata, checking signature");
                    if (!consumerProcessor.isSignatureGood(samlResponse.getSignature())) {
                        Assert.fail("The signature is no good when it should be");
                    }
                }
                // Process the assertion contents
                Assertion gotAssertion = null;
                final Decrypter samlDecrypter = consumerProcessor.getDecrypter();
                if (samlDecrypter != null) {
                    // Check the encryption/decryption if the service expects a client to encrypt what it sends out
                    final EncryptedAssertion encryptedAssertion = samlResponse.getEncryptedAssertions().get(0);
                    if (encryptedAssertion != null) {
                        try {
                            gotAssertion = samlDecrypter.decrypt(encryptedAssertion);
                        } catch (Exception anyE) {
                            Assert.fail("Error doing decryption");
                        }
                    } else {
                        Assert.fail("With the target service we were expecting an encrypted assertion");
                    }
                } else {
                    Assert.fail("With the target service we were expecting an encrypted assertion");
                }
                // Validate the contents of the assertion and redirect to the error page if invalid
                SAMLAssertionValidationResult assertionValidationResult = consumerProcessor.validate(gotAssertion, issuer);
                if (!assertionValidationResult.isValid()) {
                    Assert.fail("Assertion provided has failed validation: " + assertionValidationResult.getErrorDetails());
                }
                // Get the identifier of the user we expect
                final String userIdentifier = gotAssertion.getSubject().getNameID().getValue();
                assertThat(userIdentifier, is("189502"));
                // Get any attributes we expected
            } else {
                Assert.fail("Missing the required details needed to processing an incoming SAML2 payload");
            }
        } catch (Exception anyE) {
            Assert.fail("Generic assertion consumer error: " + anyE.getMessage());
        }

        // Test consumption of payload holding encrypted assertion and signed response. So build a HTTP POST from 
        // customer "idp_sam2" to service "MyView" for module "payslips", user "189502", with no extra attributes.
        try {
            SAMLMessageContext context = new BasicSAMLMessageContext();
            Map<String, String> attributes = new HashMap<String, String>(0);
            attributes.put("role", "code monkey");
            attributes.put("expectation", "low to middling");
            context.setInboundMessageTransport(new HttpServletRequestAdapter(
                    buildIncomingHTTPRequest("idp_saml2", "MyView", "payslips", "189502", attributes)));
            HTTPPostDecoder messageDecoder = new HTTPPostDecoder();
            messageDecoder.decode(context);
            final InboundSAML2Message message = classUnderTest.getMessageDetails(context);
            if (message.hasRequiredDetails()) {
                final String issuer = message.getIssuer();
                final String relayState = message.getRelayState();
                final Response samlResponse = message.getResponse();
                assertThat(issuer, is("idp_saml2"));
                assertThat(relayState, is("payslips"));
                // Get the redirection details we would use to back-door authorise with some service, and 
                // use to determine our service re-direction strategy following successful back-door authorisation
                final ConsumerRedirectionConfiguration redirectConfig = classUnderTest.getRedirectConfig(issuer);
                assertThat(redirectConfig.getServiceCode(), is("MyView"));
                assertThat(redirectConfig.getCustomerCode(), is("idp_saml2"));
                // Use the consumer processor to process the new arrival
                SAML2AssertionConsumerProcessor consumerProcessor = classUnderTest.getProcessor(issuer);
                // Validate the SAML response content
                SAMLResponseValidationResult responseValidationResult = consumerProcessor.validate(samlResponse);
                if (!responseValidationResult.isValid()) {
                    Assert.fail("Response provided has failed validation: " + responseValidationResult.getErrorDetails());
                }
                // Check the signature if the consumer signs the SAML requests it sends
                if (consumerProcessor.idpSignsMessages()) {
                    log.debug("Issuer " + issuer + " signs its SAML content according to our shared metadata, checking signature");
                    if (!consumerProcessor.isSignatureGood(samlResponse.getSignature())) {
                        Assert.fail("The signature is no good when it should be");
                    }
                }
                // Process the assertion contents
                Assertion gotAssertion = null;
                final Decrypter samlDecrypter = consumerProcessor.getDecrypter();
                if (samlDecrypter != null) {
                    // Check the encryption/decryption if the service expects a client to encrypt what it sends out
                    final EncryptedAssertion encryptedAssertion = samlResponse.getEncryptedAssertions().get(0);
                    if (encryptedAssertion != null) {
                        try {
                            gotAssertion = samlDecrypter.decrypt(encryptedAssertion);
                        } catch (Exception anyE) {
                            Assert.fail("Error doing decryption");
                        }
                    } else {
                        Assert.fail("With the target service we were expecting an encrypted assertion");
                    }
                } else {
                    Assert.fail("With the target service we were expecting an encrypted assertion");
                }
                // Validate the contents of the assertion and redirect to the error page if invalid
                SAMLAssertionValidationResult assertionValidationResult = consumerProcessor.validate(gotAssertion, issuer);
                if (!assertionValidationResult.isValid()) {
                    Assert.fail("Assertion provided has failed validation: " + assertionValidationResult.getErrorDetails());
                }
                // Get the identifier of the user we expect
                final String userIdentifier = gotAssertion.getSubject().getNameID().getValue();
                assertThat(userIdentifier, is("189502"));
                // Get any attributes we expected
                List<AttributeStatement> attributeStatements = gotAssertion.getAttributeStatements();
                assertThat(attributeStatements, notNullValue());
                assertThat(attributeStatements.size(), is(1));
                final List<Attribute> gotAttributes = attributeStatements.get(0).getAttributes();
                assertThat(gotAttributes.size(), is(2));
                for (Attribute attribute : gotAttributes) {
                    if (attribute.getName().equals("role")) {
                        assertThat(attribute.getDOM().getTextContent(), is("code monkey"));
                    }
                    if (attribute.getName().equals("expectation")) {
                        assertThat(attribute.getDOM().getTextContent(), is("low to middling"));
                    }
                }
            } else {
                Assert.fail("Missing the required details needed to processing an incoming SAML2 payload");
            }
        } catch (Exception anyE) {
            Assert.fail("Generic assertion consumer error: " + anyE.getMessage());
        }


        // Test consumption of payload holding encrypted assertion and signed response. So build a HTTP POST from 
        // customer "idp_sam2" to service "MyView" for the main page, user "189502", with no extra attributes.
        try {
            SAMLMessageContext context = new BasicSAMLMessageContext();
            context.setInboundMessageTransport(new HttpServletRequestAdapter(
                    buildIncomingHTTPRequest("idp_saml2", "MyView", null, "189502", null)));
            HTTPPostDecoder messageDecoder = new HTTPPostDecoder();
            messageDecoder.decode(context);
            final InboundSAML2Message message = classUnderTest.getMessageDetails(context);
            if (message.hasRequiredDetails()) {
                final String issuer = message.getIssuer();
                final String relayState = message.getRelayState();
                final Response samlResponse = message.getResponse();
                assertThat(issuer, is("idp_saml2"));
                // Relay state (or module) wasn't provided so should be null
                Assert.assertNull(relayState);
                // Get the redirection details we would use to back-door authorise with some service, and 
                // use to determine our service re-direction strategy following successful back-door authorisation
                final ConsumerRedirectionConfiguration redirectConfig = classUnderTest.getRedirectConfig(issuer);
                assertThat(redirectConfig.getServiceCode(), is("MyView"));
                assertThat(redirectConfig.getCustomerCode(), is("idp_saml2"));
                // Use the consumer processor to process the new arrival
                SAML2AssertionConsumerProcessor consumerProcessor = classUnderTest.getProcessor(issuer);
                // Validate the SAML response content
                SAMLResponseValidationResult responseValidationResult = consumerProcessor.validate(samlResponse);
                if (!responseValidationResult.isValid()) {
                    Assert.fail("Response provided has failed validation: " + responseValidationResult.getErrorDetails());
                }
                // Check the signature if the consumer signs the SAML requests it sends
                if (consumerProcessor.idpSignsMessages()) {
                    log.debug("Issuer " + issuer + " signs its SAML content according to our shared metadata, checking signature");
                    if (!consumerProcessor.isSignatureGood(samlResponse.getSignature())) {
                        Assert.fail("The signature is no good when it should be");
                    }
                }
                // Process the assertion contents
                Assertion gotAssertion = null;
                final Decrypter samlDecrypter = consumerProcessor.getDecrypter();
                if (samlDecrypter != null) {
                    // Check the encryption/decryption if the service expects a client to encrypt what it sends out
                    final EncryptedAssertion encryptedAssertion = samlResponse.getEncryptedAssertions().get(0);
                    if (encryptedAssertion != null) {
                        try {
                            gotAssertion = samlDecrypter.decrypt(encryptedAssertion);
                        } catch (Exception anyE) {
                            Assert.fail("Error doing decryption");
                        }
                    } else {
                        Assert.fail("With the target service we were expecting an encrypted assertion");
                    }
                } else {
                    Assert.fail("With the target service we were expecting an encrypted assertion");
                }
                // Validate the contents of the assertion and redirect to the error page if invalid
                SAMLAssertionValidationResult assertionValidationResult = consumerProcessor.validate(gotAssertion, issuer);
                if (!assertionValidationResult.isValid()) {
                    Assert.fail("Assertion provided has failed validation: " + assertionValidationResult.getErrorDetails());
                }
                // Get the identifier of the user we expect
                final String userIdentifier = gotAssertion.getSubject().getNameID().getValue();
                assertThat(userIdentifier, is("189502"));
                // Get any attributes we expected
            } else {
                Assert.fail("Missing the required details needed to processing an incoming SAML2 payload");
            }
        } catch (Exception anyE) {
            Assert.fail("Generic assertion consumer error: " + anyE.getMessage());
        }

        // Test consumption of payload holding encrypted assertion and signed response. So build a HTTP POST from
        // customer "idp_sam2" to service "MyView" with a deliberately empty string relayState, user "189502", with
        // no extra attributes.
        try {
            SAMLMessageContext context = new BasicSAMLMessageContext();
            context.setInboundMessageTransport(new HttpServletRequestAdapter(
                    buildIncomingHTTPRequest("idp_saml2", "MyView", "", "189502", null)));
            HTTPPostDecoder messageDecoder = new HTTPPostDecoder();
            messageDecoder.decode(context);
            final InboundSAML2Message message = classUnderTest.getMessageDetails(context);
            if (message.hasRequiredDetails()) {
                final String issuer = message.getIssuer();
                final String relayState = message.getRelayState();
                final Response samlResponse = message.getResponse();
                assertThat(issuer, is("idp_saml2"));
                // Relay state (or module) even if its empty should be reported as null
                Assert.assertNull(relayState);
                // Get the redirection details we would use to back-door authorise with some service, and
                // use to determine our service re-direction strategy following successful back-door authorisation
                final ConsumerRedirectionConfiguration redirectConfig = classUnderTest.getRedirectConfig(issuer);
                assertThat(redirectConfig.getServiceCode(), is("MyView"));
                assertThat(redirectConfig.getCustomerCode(), is("idp_saml2"));
                // Use the consumer processor to process the new arrival
                SAML2AssertionConsumerProcessor consumerProcessor = classUnderTest.getProcessor(issuer);
                // Validate the SAML response content
                SAMLResponseValidationResult responseValidationResult = consumerProcessor.validate(samlResponse);
                if (!responseValidationResult.isValid()) {
                    Assert.fail("Response provided has failed validation: " + responseValidationResult.getErrorDetails());
                }
                // Check the signature if the consumer signs the SAML requests it sends
                if (consumerProcessor.idpSignsMessages()) {
                    log.debug("Issuer " + issuer + " signs its SAML content according to our shared metadata, checking signature");
                    if (!consumerProcessor.isSignatureGood(samlResponse.getSignature())) {
                        Assert.fail("The signature is no good when it should be");
                    }
                }
                // Process the assertion contents
                Assertion gotAssertion = null;
                final Decrypter samlDecrypter = consumerProcessor.getDecrypter();
                if (samlDecrypter != null) {
                    // Check the encryption/decryption if the service expects a client to encrypt what it sends out
                    final EncryptedAssertion encryptedAssertion = samlResponse.getEncryptedAssertions().get(0);
                    if (encryptedAssertion != null) {
                        try {
                            gotAssertion = samlDecrypter.decrypt(encryptedAssertion);
                        } catch (Exception anyE) {
                            Assert.fail("Error doing decryption");
                        }
                    } else {
                        Assert.fail("With the target service we were expecting an encrypted assertion");
                    }
                } else {
                    Assert.fail("With the target service we were expecting an encrypted assertion");
                }
                // Validate the contents of the assertion and redirect to the error page if invalid
                SAMLAssertionValidationResult assertionValidationResult = consumerProcessor.validate(gotAssertion, issuer);
                if (!assertionValidationResult.isValid()) {
                    Assert.fail("Assertion provided has failed validation: " + assertionValidationResult.getErrorDetails());
                }
                // Get the identifier of the user we expect
                final String userIdentifier = gotAssertion.getSubject().getNameID().getValue();
                assertThat(userIdentifier, is("189502"));
                // Get any attributes we expected
            } else {
                Assert.fail("Missing the required details needed to processing an incoming SAML2 payload");
            }
        } catch (Exception anyE) {
            Assert.fail("Generic assertion consumer error: " + anyE.getMessage());
        }

        try {
            propsStream = new FileInputStream(new File(PROPERTIES_FILE));
            entityTranslationStream = new FileInputStream(new File(ENTITY_TRANSLATION_FILE));
            metadataStream = new FileInputStream(new File(META_DATA_FILE));
            privateKeyStream = new FileInputStream(new File(PRIVATE_DECRYPTION_KEY_FILE));
        } catch (Exception anyE) {
            Assert.fail("Error creating streams");
        }

        // Test consumption of payload holding unencrypted assertion and signed response. So build a HTTP POST from
        // customer "idp_sam2" to service "SimpleService" with null relayState, and user "1234", with no extra 
        // attributes.
        classUnderTest =
                new SAML2AssertionConsumer("SimplestService", propsStream, entityTranslationStream, metadataStream, privateKeyStream);
        try {
            SAMLMessageContext context = new BasicSAMLMessageContext();
            context.setInboundMessageTransport(new HttpServletRequestAdapter(
                    buildIncomingHTTPRequest("idp_saml2", "SimplestService", null, "1234", null)));
            HTTPPostDecoder messageDecoder = new HTTPPostDecoder();
            messageDecoder.decode(context);
            final InboundSAML2Message message = classUnderTest.getMessageDetails(context);
            if (message.hasRequiredDetails()) {
                final String issuer = message.getIssuer();
                final String relayState = message.getRelayState();
                final Response samlResponse = message.getResponse();
                assertThat(issuer, is("idp_saml2"));
                // Relay state (or module) even if its empty should be reported as null
                Assert.assertNull(relayState);
                // Get the redirection details we would use to back-door authorise with some service, and
                // use to determine our service re-direction strategy following successful back-door authorisation
                final ConsumerRedirectionConfiguration redirectConfig = classUnderTest.getRedirectConfig(issuer);
                assertThat(redirectConfig.getServiceCode(), is("SimplestService"));
                assertThat(redirectConfig.getCustomerCode(), is("idp_saml2"));
                // Use the consumer processor to process the new arrival
                SAML2AssertionConsumerProcessor consumerProcessor = classUnderTest.getProcessor(issuer);
                // Validate the SAML response content
                SAMLResponseValidationResult responseValidationResult = consumerProcessor.validate(samlResponse);
                if (!responseValidationResult.isValid()) {
                    Assert.fail("Response provided has failed validation: " + responseValidationResult.getErrorDetails());
                }
                // Check the signature if the consumer signs the SAML requests it sends
                if (consumerProcessor.idpSignsMessages()) {
                    log.debug("Issuer " + issuer + " signs its SAML content according to our shared metadata, checking signature");
                    if (!consumerProcessor.isSignatureGood(samlResponse.getSignature())) {
                        Assert.fail("The signature is no good when it should be");
                    }
                }
                // Process the assertion contents
                Assertion gotAssertion = null;
                final Decrypter samlDecrypter = consumerProcessor.getDecrypter();
                if (samlDecrypter != null) {
                    Assert.fail("With the simple service we do not expect any encryption");
                } else {
                    gotAssertion = samlResponse.getAssertions().get(0);
                }
                // Validate the contents of the assertion and redirect to the error page if invalid
                SAMLAssertionValidationResult assertionValidationResult = consumerProcessor.validate(gotAssertion, issuer);
                if (!assertionValidationResult.isValid()) {
                    Assert.fail("Assertion provided has failed validation: " + assertionValidationResult.getErrorDetails());
                }
                // Get the identifier of the user we expect
                final String userIdentifier = gotAssertion.getSubject().getNameID().getValue();
                assertThat(userIdentifier, is("1234"));
                // Get any attributes we expected
            } else {
                Assert.fail("Missing the required details needed to processing an incoming SAML2 payload");
            }
        } catch (Exception anyE) {
            Assert.fail("Generic assertion consumer error: " + anyE.getMessage());
        }

        // Test consumption of payload holding unencrypted assertion and unsigned response. So build a HTTP POST from
        // customer "SimplestProducer" to service "SimpleService" with null relayState, and user "345", with no extra 
        // attributes.
        try {
            SAMLMessageContext context = new BasicSAMLMessageContext();
            context.setInboundMessageTransport(new HttpServletRequestAdapter(
                    buildIncomingHTTPRequest("SimplestProducer", "SimplestService", null, "345", null)));
            HTTPPostDecoder messageDecoder = new HTTPPostDecoder();
            messageDecoder.decode(context);
            final InboundSAML2Message message = classUnderTest.getMessageDetails(context);
            if (message.hasRequiredDetails()) {
                final String issuer = message.getIssuer();
                final String relayState = message.getRelayState();
                final Response samlResponse = message.getResponse();
                assertThat(issuer, is("SimplestProducer"));
                // Relay state (or module) even if its empty should be reported as null
                Assert.assertNull(relayState);
                // Get the redirection details we would use to back-door authorise with some service, and
                // use to determine our service re-direction strategy following successful back-door authorisation
                final ConsumerRedirectionConfiguration redirectConfig = classUnderTest.getRedirectConfig(issuer);
                assertThat(redirectConfig.getServiceCode(), is("SimplestService"));
                assertThat(redirectConfig.getCustomerCode(), is("SimplestProducer"));
                // Use the consumer processor to process the new arrival
                SAML2AssertionConsumerProcessor consumerProcessor = classUnderTest.getProcessor(issuer);
                // Validate the SAML response content
                SAMLResponseValidationResult responseValidationResult = consumerProcessor.validate(samlResponse);
                if (!responseValidationResult.isValid()) {
                    Assert.fail("Response provided has failed validation: " + responseValidationResult.getErrorDetails());
                }
                // Check the signature if the consumer signs the SAML requests it sends
                if (consumerProcessor.idpSignsMessages()) {
                    Assert.fail("The SimplestProducer doesn't do digital signatures");
                }
                // Process the assertion contents
                Assertion gotAssertion = null;
                final Decrypter samlDecrypter = consumerProcessor.getDecrypter();
                if (samlDecrypter != null) {
                    Assert.fail("With the simple service we do not expect any encryption");
                } else {
                    gotAssertion = samlResponse.getAssertions().get(0);
                }
                // Validate the contents of the assertion and redirect to the error page if invalid
                SAMLAssertionValidationResult assertionValidationResult = consumerProcessor.validate(gotAssertion, issuer);
                if (!assertionValidationResult.isValid()) {
                    Assert.fail("Assertion provided has failed validation: " + assertionValidationResult.getErrorDetails());
                }
                // Get the identifier of the user we expect
                final String userIdentifier = gotAssertion.getSubject().getNameID().getValue();
                assertThat(userIdentifier, is("345"));
                // Get any attributes we expected
            } else {
                Assert.fail("Missing the required details needed to processing an incoming SAML2 payload");
            }
        } catch (Exception anyE) {
            Assert.fail("Generic assertion consumer error: " + anyE.getMessage());
        }
    }

    /**
     * Build an incoming HttpServletRequest holding the contents of a POSTed SAML2 base64 encoded payload that makes
     * sense given the producer name, and service name, and the consequently looked up meta-data which drives whether
     * the contents are encrypted and signed.
     *
     * @param producerName   producer name (so who the assertion is pretending to come from)
     * @param serviceName    service name (so for what service the assertion is pretending to be for)
     * @param relayState     contextual information for the destination service used to determine the "deep-dive" module to
     *                       navigate too in the destinatino service.
     * @param userIdentifier user identifier at the destination service (asserted identity)
     * @param attributes     Any extra SAML attributes you might like to associate with the assertion
     * @return dummy HttpServletRequest with the encoded payload
     */
    private HttpServletRequest buildIncomingHTTPRequest(final String producerName,
                                                        final String serviceName,
                                                        final String relayState,
                                                        final String userIdentifier,
                                                        final Map<String, String> attributes) {
        try {
            SAML2AssertionProducer producer =
                    new SAML2AssertionProducer(producerName, serviceName, HANDLER, PROPERTIES_FILE,
                            ENTITY_TRANSLATION_FILE, META_DATA_FILE, PRIVATE_SIGNING_KEY_FILE);
            final String payload = producer.getSAMLResponsePayload(userIdentifier, attributes);
            /*
            The destination end point URL for SAML2 is obtained from the service definition in meta-data, for SAML2
            this means the Location attribute of an AssertionConsumerService definition, for example:-
            
             <AssertionConsumerService isDefault="true" index="0"
                                      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                      Location="http://pc33767.uk.rebushr.com:8080/SAMLWeb/myview/SAML2AssertionConsumer"/>
             */
            final String destination = producer.getDestinationEndpointURL();
            return populateRequest(payload, relayState, destination);
        } catch (Exception anyE) {
            throw new RuntimeException("Cannot create sample HttpServletRequest", anyE);
        }
    }

    /**
     * Return a populated mock HTTP request that represents the content of a hidden POST holding the right parameters
     * and values for the SAML2 POST Web Profile (scenario but in SAML speak), going to the right "destination" for
     * the intended service.
     *
     * @param samlPayload SAML payload
     * @param relayState  relay state
     * @param destination destination URL
     * @return mocked request holding valid SAML2 content
     */
    private HttpServletRequest populateRequest(final String samlPayload,
                                               final String relayState,
                                               final String destination) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        populateRequestURL(request, destination);
        request.setMethod("POST");
        request.addHeader("Content-Type", "application/x-www-form-urlencoded");
        request.addParameter("SAMLResponse", samlPayload);
        if (relayState != null) {
            request.addParameter("RelayState", relayState);
        }
        return request;
    }

    /**
     * The SAML specification states that if the actual destination URL found in an HTTP request holding incoming SAML
     * payload differs from the endpoint destination URL defined for a service defined in shared SAML meta-data, then
     * the request should be declined by the service.  Frankly this security measure is a complete pain in the arse
     * for services that live behind proxies whose public FQDN differs from the internal FQDN, like all of ours do
     * in Northgate hosting.
     * <p/>
     * So, this explains the reason for two versions of meta-data. One we give to customers to "our" services, so the
     * public facing SAML meta-data whose end point location URLs for assertion consumer services are the publicly
     * addressable points of access we as a company provide.  The other version of meta-data is for us (in hosting)
     * that uses the internal (behind the hosting session border controller) assertion consumer addresses for our
     * SAML consumers.  Why? because the proxy that sends requests to the right place within hosting WILL always
     * translate between the public outward facing location URL, and the inward facing location URL, as this is
     * what proxy's do.
     * <p/>
     * Here we populate enough in the mock servlet request to fool the context parser used within a assertion consumer
     * that the request is a genuine HTTP request from some external client to the intended service.
     *
     * @param request     request to decorate with URL meaningful content.
     * @param destination assertion consumer destination end point URL
     */
    private void populateRequestURL(MockHttpServletRequest request, String destination) {
        URL url;
        try {
            url = new URL(destination);
        } catch (MalformedURLException e) {
            throw new RuntimeException("Error parsing the URL for the end point destination found in meta-data " + destination);
        }
        request.setScheme(url.getProtocol());
        request.setServerName(url.getHost());
        if (url.getPort() != -1) {
            request.setServerPort(url.getPort());
        } else {
            if ("https".equalsIgnoreCase(url.getProtocol())) {
                request.setServerPort(443);
            } else if ("http".equalsIgnoreCase(url.getProtocol())) {
                request.setServerPort(80);
            }
        }
        request.setRequestURI(url.getPath());
        request.setQueryString(url.getQuery());
    }
}