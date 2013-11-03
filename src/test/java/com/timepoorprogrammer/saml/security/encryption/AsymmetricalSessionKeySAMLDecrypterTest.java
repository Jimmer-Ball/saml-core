package com.timepoorprogrammer.saml.security.encryption;

import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.core.SAML2Handler;
import com.timepoorprogrammer.saml.core.IOHelper;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import com.timepoorprogrammer.saml.security.encryption.AsymmetricalSessionKeySAMLDecrypter;
import org.junit.Test;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.XMLObject;
import org.opensaml.common.SAMLVersion;
import org.joda.time.DateTime;

import java.io.InputStream;
import java.util.Date;
import java.util.List;

public class AsymmetricalSessionKeySAMLDecrypterTest  {
    @Test
    public void testDecryptAssertion() {
        SAML2Handler handler = new SAML2Handler();
        IOHelper ioHelper = new IOHelper();
        // Get hold of our keystore
        final String keyStorePath = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\serviceKeyStore.jks$");
        // Create a decrypter passing in the path ot the store, the store password and the
        // password required for the private key.
        final AsymmetricalSessionKeySAMLDecrypter decrypter =
                new AsymmetricalSessionKeySAMLDecrypter(keyStorePath, "rmi+ssl", "remoteservice", "remoteservice");
        // Get hold of our test data
        final EncryptedAssertion encryptedAssertion = getValidEncryptedAuthenticationAssertion(handler, ioHelper);
        // Decrypt our test data
        final Assertion gotAssertion = decrypter.decryptAssertion(encryptedAssertion);

              // TODO: We check the SAML version is valid
        assertThat(gotAssertion.getVersion(), is(SAMLVersion.VERSION_20));
        assertThat(gotAssertion.getIssuer(), notNullValue());

        // TODO: What constitutes a valid issuer?
        assertThat(gotAssertion.getIssuer().getValue(), is("http://timewarner.com/IDPService"));

        // TODO: What constitues a valid format for the NameID, as it could be many different formats?
        assertThat(gotAssertion.getSubject(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID().getValue(), is("1895021000"));
        assertTrue(gotAssertion.getSubject().getNameID().getFormat().equals(NameIDType.PERSISTENT));

        // TODO: We could even have an SP identifier here to cover the mapping of TWID to MyView identifier if needed
        //final String weCouldUseThis = gotAssertion.getSubject().getNameID().getSPProvidedID();

        // TODO: What consitutes validity for NotBefore and NotOnOrAfter?
        assertThat(gotAssertion.getConditions(), notNullValue());
        final Conditions conditions = gotAssertion.getConditions();
        assertThat(conditions, notNullValue());
        final DateTime notBefore = conditions.getNotBefore();
        Date now = new Date();
        assertTrue(notBefore.toDate().before(now));

        // Process the authentication statements
        final List<AuthnStatement> authnStatements = gotAssertion.getAuthnStatements();
        assertThat(authnStatements, notNullValue());
        assertThat(authnStatements.size(), is(1));
        final AuthnStatement authenticationType = authnStatements.get(0);
        // TODO: What type (if we actually care) should this authentication type be? Note: The nesting on the getAuthContextClassRef, it has a wierd structure eh?
        assertTrue(AuthnContext.PPT_AUTHN_CTX.equals(authenticationType.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef()));

        // TODO: We could even have attribute statements in this that hold the MyView identifier
        
        handler.printToFile(gotAssertion, null);
    }

    @Test
    public void testTWDecryptAssertion() {
        SAML2Handler handler = new SAML2Handler();
        IOHelper ioHelper = new IOHelper();
        // Get hold of our keystore
        final String keyStorePath = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\serviceKeyStore.jks$");
        // Create a decrypter passing in the path ot the store, the store password and the
        // password required for the private key.
        final AsymmetricalSessionKeySAMLDecrypter decrypter =
                new AsymmetricalSessionKeySAMLDecrypter(keyStorePath, "rmi+ssl", "remoteservice", "remoteservice");
        // Get hold of our test data
        final EncryptedAssertion encryptedAssertion = getValidTWEncryptedAuthenticationAssertion(handler, ioHelper);
        // Decrypt our test data
        final Assertion gotAssertion = decrypter.decryptAssertion(encryptedAssertion);

        // TODO: We check the SAML version is valid
        assertThat(gotAssertion.getVersion(), is(SAMLVersion.VERSION_20));
        assertThat(gotAssertion.getIssuer(), notNullValue());

        // TODO: What constitutes a valid issuer?
        assertThat(gotAssertion.getIssuer().getValue(), is("https://twservices.dev.timewarner.com/TWSAMLService"));

        // TODO: What constitues a valid format for the NameID, as it could be many different formats?
        assertThat(gotAssertion.getSubject(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID().getValue(), is("0007058473@tw|9/20/2010 10:43:03 PM@tw"));
        assertTrue(gotAssertion.getSubject().getNameID().getFormat().equals(NameIDType.UNSPECIFIED));

        // TODO: We could even have an SP identifier here to cover the mapping of TWID to MyView identifier if needed
        //final String weCouldUseThis = gotAssertion.getSubject().getNameID().getSPProvidedID();

        // TODO: What consitutes validity for NotBefore and NotOnOrAfter? The TimeWarner guys sent us sample data whose after expired ages back, so no after check performed
        assertThat(gotAssertion.getConditions(), notNullValue());
        final Conditions conditions = gotAssertion.getConditions();
        assertThat(conditions, notNullValue());
        final DateTime notBefore = conditions.getNotBefore();
        Date now = new Date();
        assertTrue(notBefore.toDate().before(now));

        // Process the authentication statements
        final List<AuthnStatement> authnStatements = gotAssertion.getAuthnStatements();
        assertThat(authnStatements, notNullValue());
        assertThat(authnStatements.size(), is(1));
        final AuthnStatement authenticationType = authnStatements.get(0);
        // TODO: What type (if we actually care) should this authentication type be? Note: The nesting on the getAuthContextClassRef, it has a wierd structure eh?
        assertTrue(AuthnContext.PASSWORD_AUTHN_CTX.equals(authenticationType.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef()));

        // TODO: We could even have attribute statements in this that hold the MyView identifier

        handler.printToFile(gotAssertion, null);
    }


    /**
     * Go look at the sample encrypted SAML Authentication assertion in fixtures/canned_saml/Assertion
     *
     * @param handler SAML handler
     * @param ioHelper io helper
     * @return encrypted assertion
     */
    private EncryptedAssertion getValidEncryptedAuthenticationAssertion(final SAML2Handler handler, final IOHelper ioHelper) {
        // Lets read in our EncryptedAssertion from file that represents what we want to be decrypted
        final String authAssertionPath = TestHelper.getFullPath("^.*fixtures\\\\canned_saml\\\\Assertion\\\\Authn_encrypted.xml$");
        final InputStream authAssertionStream = ioHelper.openFileAsInputStream(authAssertionPath);
        final XMLObject returnedObject = handler.readFromStream(authAssertionStream);
        assertThat(returnedObject, notNullValue());
        assertTrue(returnedObject instanceof EncryptedAssertion);
        return (EncryptedAssertion) returnedObject;
    }


       private EncryptedAssertion getValidTWEncryptedAuthenticationAssertion(final SAML2Handler handler, final IOHelper ioHelper) {
        // Lets read in our EncryptedAssertion from file that represents what we want to be decrypted
           final String authAssertionPath = TestHelper.getFullPath("^.*fixtures\\\\canned_saml\\\\Assertion\\\\TWAuthn_encrypted.xml$");
        final InputStream authAssertionStream = ioHelper.openFileAsInputStream(authAssertionPath);
        final XMLObject returnedObject = handler.readFromStream(authAssertionStream);
        assertThat(returnedObject, notNullValue());
        assertTrue(returnedObject instanceof EncryptedAssertion);
        return (EncryptedAssertion) returnedObject;
    }
}