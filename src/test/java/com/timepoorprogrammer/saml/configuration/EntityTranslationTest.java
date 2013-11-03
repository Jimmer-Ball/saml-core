package com.timepoorprogrammer.saml.configuration;

import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.configuration.EntityTranslation;
import org.junit.Test;

import java.util.Properties;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * EntityTranslation test class for going to and from SAML entity identifiers to some internal
 * customer or service codes.
 *
 * @author Jim Ball
 */
public class EntityTranslationTest {
    private static final String pathToProperties = TestHelper.getFullPath("^.*fixtures\\\\configuration\\\\samlentitytranslation.properties$");

    /**
     * Test we throw an exception when no translation file is available
     */
    @Test(expected = RuntimeException.class)
    public void testConstructor_NoConfigurationFile() {
        new EntityTranslation("fixtures/configuration/dave.txt");
    }

    /**
     * Check we can lookup a customer code correctly when a translation exists between
     * entity identifier and customer code.
     */
    @Test
    public void testLookupInternalCodeUsingEntityIdentifier_Found() {
        final EntityTranslation classUnderTest = new EntityTranslation(pathToProperties);
        final String customerCode = classUnderTest.lookupInternalCodeUsingEntityIdentifier("https://fed-uat.baplc.com/fed/idp");
        assertThat(customerCode, is("FY"));
    }

    /**
     * Check we can lookup a customer code correctly when a translation exists between
     * entity identifier and customer code, and the properties are injected (like say in MyView2).
     */
    @Test
    public void testLookupInternalCodeUsingEntityIdentifier_InjectedFound() {
        Properties injectedProperties = new Properties();
        injectedProperties.setProperty("FY", "https://fed-uat.baplc.com/fed/idp");
        final EntityTranslation classUnderTest = new EntityTranslation(injectedProperties);
        final String customerCode = classUnderTest.lookupInternalCodeUsingEntityIdentifier("https://fed-uat.baplc.com/fed/idp");
        assertThat(customerCode, is("FY"));
    }

    /**
     * Check we can lookup a customer code correctly when a translation does not exist
     * between an entity identifier and an internal customer code.
     */
    @Test
    public void testLookupInternalCodeUsingEntityIdentifier_NotFound() {
        final EntityTranslation classUnderTest = new EntityTranslation(pathToProperties);
        final String customerCode = classUnderTest.lookupInternalCodeUsingEntityIdentifier("NZ");
        assertThat(customerCode, is("NZ"));
    }

    /**
     * Check we throw an exception when a null entity identifier string is provided
     */
    @Test(expected = RuntimeException.class)
    public void testLookupInternalCodeUsingEntityIdentifier_NullCustomerCodeProvided() {
        final EntityTranslation classUnderTest = new EntityTranslation(pathToProperties);
        classUnderTest.lookupInternalCodeUsingEntityIdentifier(null);
    }

    /**
     * Check we can lookup an entity identifier correctly when a translation exists between
     * an internal customer code and an entity identifier.
     */
    @Test
    public void testLookupEntityIdentifierUsingInternalCode_Found() {
        final EntityTranslation classUnderTest = new EntityTranslation(pathToProperties);
        final String customerCode = classUnderTest.lookupEntityIdentifierUsingInternalCode("FY");
        assertThat(customerCode, is("https://fed-uat.baplc.com/fed/idp"));
    }

    /**
     * Check we can lookup an entity identifier correctly when a translation does not exist
     * between a customer code and an entity identifier
     */
    @Test
    public void testLookupEntityIdentifierUsingInternalCode_NotFound() {
        final EntityTranslation classUnderTest = new EntityTranslation(pathToProperties);
        final String customerCode = classUnderTest.lookupEntityIdentifierUsingInternalCode("NZ");
        assertThat(customerCode, is("NZ"));
    }

    /**
     * Check we throw an exception when a null internal customer code is provided
     */
    @Test(expected = RuntimeException.class)
    public void testLookupEntityIdentifierUsingInternalCode_NullIssuerProvided() {
        final EntityTranslation classUnderTest = new EntityTranslation(pathToProperties);
        classUnderTest.lookupEntityIdentifierUsingInternalCode(null);
    }

}