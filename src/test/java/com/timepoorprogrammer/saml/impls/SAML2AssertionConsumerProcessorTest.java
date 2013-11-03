package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.configuration.ConfigurationProperties;
import com.timepoorprogrammer.saml.configuration.ConsumerConfiguration;
import com.timepoorprogrammer.saml.configuration.EntityTranslation;
import com.timepoorprogrammer.saml.core.SAML2Handler;
import com.timepoorprogrammer.saml.impls.MetaDataHandler;
import com.timepoorprogrammer.saml.impls.MetaDataHandlerFactory;
import com.timepoorprogrammer.saml.impls.SAML2AssertionConsumerProcessor;
import com.timepoorprogrammer.saml.impls.SAML2AssertionConsumerProcessorFactory;
import org.junit.Assert;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * Test class for the assertion consumer which also illustrates how every single
 * factory in the whole project actually works in terms of picking up default
 * implementations and bespoke implementations from a standard sub package
 * organisation to be used for every single customer bespoke work needs to be done for.
 *
 * @author Jim Ball
 */
public class SAML2AssertionConsumerProcessorTest {

    /**
     * The name of the assertion consumer we are
     */
    private static final String ASSERTION_CONSUMER_NAME = "MyView";

    /**
     * Properties file used by the assertion consumer
     */
    private static final String PROPERTIES_FILE = TestHelper.getFullPath("^.*fixtures\\\\configuration\\\\saml.properties$");

    /**
     * Properties file holding lookup details between SAML Issuer details and our Northgate internal
     * customer code.
     */
    private static final String ENTITY_TRANSLATION_FILE = TestHelper.getFullPath("^.*fixtures\\\\configuration\\\\samlentitytranslation.properties$");

    /**
     * Issuer details, which correspond to the customer code and the organisation of the code
     */
    private static final String ISSUER = "NZ";

    // To test a processor requires an initialised SAML library which means an initialed handler
    public static final SAML2Handler GOTTA_HAVE_A_HANDLER = new SAML2Handler();

    /**
     * Test the return of the default SAML2AssertionConsumerProcessor is correct.
     * <p/>
     * This can be used to validate all the factories work the same way too in terms of picking up
     * a bespoke implementation via a factory along the path of
     * com.ngahr.saml.impls.<lowercase_customer_code>.<whatever_the_subdirectory_is_for_the_factory>.<interface_name>Impl
     */
    @Test
    public void testDefaults() {
        try {
            final ConfigurationProperties properties = new ConfigurationProperties(PROPERTIES_FILE);
            final ConsumerConfiguration config = new ConsumerConfiguration(properties, ASSERTION_CONSUMER_NAME);
            final MetaDataHandler mdHandler = MetaDataHandlerFactory.getInstance(null);

            // See if we have a customer code for this user that differs from the provided Issuer details string
            final EntityTranslation lookup = new EntityTranslation(ENTITY_TRANSLATION_FILE);

            final String customerCode = lookup.lookupInternalCodeUsingEntityIdentifier("idp_saml2");

            // Create a default consumer processor
            final String mdFilePath = TestHelper.getFullPath("^.*fixtures\\\\metadata\\\\" + config.getMetadataFileName() + "$");
            final String privateKeyStorePath = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\" + config.getKeyStoreName() + "$");
            SAML2AssertionConsumerProcessor explicitProcessor =
                    SAML2AssertionConsumerProcessorFactory.getInstance(mdFilePath, "idp_saml2", customerCode,
                            SAMLConstants.SAML20P_NS, ASSERTION_CONSUMER_NAME, mdHandler, privateKeyStorePath,
                            config.getKeyStorePassword(), config.getDecryptionKeyAlias(),
                            config.getDecryptionKeyPassword());

            final Class explicitClass = explicitProcessor.getClass();
            assertThat(explicitClass.getName(), is("com.timepoorprogrammer.saml.impls.standard.consumer.processor.SAML2AssertionConsumerProcessorImpl"));
        } catch (Exception anyE) {
            Assert.fail("Error running processor factory main scenario test " + anyE.getMessage());
        }
    }

    /**
     * Test the return of a bespoke processor is correct.
     * <p/>
     * This can be used to validate all the factories work the same way too in terms of picking up
     * a bespoke implementation via a factory along the path of
     * com.ngahr.saml.impls.<lowercase_customer_code>.<whatever_the_subdirectory_is_for_the_factory>.<interface_name>Impl
     */
    @Test
    public void testBespoke() {
        try {
            final ConfigurationProperties properties = new ConfigurationProperties(PROPERTIES_FILE);
            final ConsumerConfiguration config = new ConsumerConfiguration(properties, ASSERTION_CONSUMER_NAME);
            final MetaDataHandler mdHandler = MetaDataHandlerFactory.getInstance(null);

            final String mdFilePath = TestHelper.getFullPath("^.*fixtures\\\\metadata\\\\" + config.getMetadataFileName() + "$");
            final String privateKeyStorePath = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\" + config.getKeyStoreName() + "$");

            // See if we have a customer code for this user that differs from the provided Issuer details string
            final EntityTranslation lookup = new EntityTranslation(ENTITY_TRANSLATION_FILE);
            final String customerCode = lookup.lookupInternalCodeUsingEntityIdentifier(ISSUER);

            // Create a bespoke consumer processor
            final SAML2AssertionConsumerProcessor bespokeProcessor =
                    SAML2AssertionConsumerProcessorFactory.getInstance(mdFilePath, ISSUER, customerCode,
                            SAMLConstants.SAML20P_NS, ASSERTION_CONSUMER_NAME, mdHandler, privateKeyStorePath,
                            config.getKeyStorePassword(), config.getDecryptionKeyAlias(),
                            config.getDecryptionKeyPassword());

            final Class bespokeClass = bespokeProcessor.getClass();
            assertThat(bespokeClass.getName(), is("com.timepoorprogrammer.saml.impls.nz.consumer.processor.SAML2AssertionConsumerProcessorImpl"));
        } catch (Exception anyE) {
            Assert.fail("Error running bespoke scenario test " + anyE.getMessage());
        }
    }

    /**
     * Test the return of the default consumer processor is correct when the producer code is actually British Airways
     * (FY) which has its own mapping from internal Northgate customer code to SAML entity identifier
     * <p/>
     * This can be used to validate all the factories work the same way too in terms of picking up
     * a bespoke implementation via a factory along the path of
     * com.ngahr.saml.impls.<lowercase_serviceCode>.<whatever_the_subdirectory_is_for_the_factory>.<interface_name>Impl
     */
    @Test
    public void testDefaults_withAnProperEntityDefinition() {
        try {
            final ConfigurationProperties properties = new ConfigurationProperties(PROPERTIES_FILE);

            final ConsumerConfiguration config = new ConsumerConfiguration(properties, ASSERTION_CONSUMER_NAME);
            final MetaDataHandler mdHandler = MetaDataHandlerFactory.getInstance(null);

            final String mdFilePath = TestHelper.getFullPath("^.*fixtures\\\\metadata\\\\" + config.getMetadataFileName() + "$");
            final String privateKeyStorePath = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\" + config.getKeyStoreName() + "$");

            // See if we have a customer code for this user that differs from the provided Issuer details string
            final EntityTranslation lookup = new EntityTranslation(ENTITY_TRANSLATION_FILE);
            final String customerCode = "FY";
            final String issuer = lookup.lookupEntityIdentifierUsingInternalCode(customerCode);
            assertThat(issuer, is("https://fed-uat.baplc.com/fed/idp"));

            // Create a bespoke consumer processor
            final SAML2AssertionConsumerProcessor bespokeProcessor =
                    SAML2AssertionConsumerProcessorFactory.getInstance(mdFilePath, issuer, customerCode,
                            SAMLConstants.SAML20P_NS, ASSERTION_CONSUMER_NAME, mdHandler, privateKeyStorePath,
                            config.getKeyStorePassword(), config.getDecryptionKeyAlias(),
                            config.getDecryptionKeyPassword());

            final Class bespokeClass = bespokeProcessor.getClass();
            assertThat(bespokeClass.getName(), is("com.timepoorprogrammer.saml.impls.standard.consumer.processor.SAML2AssertionConsumerProcessorImpl"));
            assertThat(bespokeProcessor.idpSignsMessages(), is(true));
        } catch (Exception anyE) {
            Assert.fail("Error running bespoke scenario test " + anyE.getMessage());
        }
    }


}