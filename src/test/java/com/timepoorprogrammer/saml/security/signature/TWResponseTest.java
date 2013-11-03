package com.timepoorprogrammer.saml.security.signature;

import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.core.IOHelper;
import com.timepoorprogrammer.saml.core.SAML2Handler;
import com.timepoorprogrammer.saml.security.encryption.AsymmetricalSessionKeySAMLDecrypter;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import org.joda.time.DateTime;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.XMLObject;

import java.io.InputStream;
import java.util.Date;
import java.util.List;

/**
 * TimeWarner response checker
 */
public class TWResponseTest {

    @Test
    public void testTWResponse() {
        SAML2Handler handler = new SAML2Handler();
        IOHelper ioHelper = new IOHelper();
        // Get hold of our keystore
        final String keyStorePath = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\serviceKeyStore.jks$");
        // Create a decrypter passing in the path ot the store, the store password and the
        // password required for the private key.
        final AsymmetricalSessionKeySAMLDecrypter decrypter =
                new AsymmetricalSessionKeySAMLDecrypter(keyStorePath, "rmi+ssl", "remoteservice", "remoteservice");
        // Get hold of our test data
        final Response response = getValidTWResponse(handler, ioHelper);
        final EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);

        // Decrypt the data they sent
        final Assertion gotAssertion = decrypter.decryptAssertion(encryptedAssertion);

        // TODO: We check the SAML version is valid
        assertThat(gotAssertion.getVersion(), is(SAMLVersion.VERSION_20));
        assertThat(gotAssertion.getIssuer(), notNullValue());

        // TODO: What constitutes a valid issuer?
        assertThat(gotAssertion.getIssuer().getValue(), is("https://twservices.dev.timewarner.com/TWSAMLService"));

        // TODO: What constitues a valid format for the NameID, as it could be many different formats?
        assertThat(gotAssertion.getSubject(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID().getValue(), is("0007058473@tw|9/21/2010 1:53:41 AM@tw"));
        assertTrue(gotAssertion.getSubject().getNameID().getFormat().equals(NameIDType.UNSPECIFIED));

        // TODO: We could even have an SP identifier here to cover the mapping of TWID to MyView identifier if needed
        //final String weCouldUseThis = gotAssertion.getSubject().getNameID().getSPProvidedID();

        // TODO: What consitutes validity for NotBefore and NotOnOrAfter?
        assertThat(gotAssertion.getConditions(), notNullValue());
        final Conditions conditions = gotAssertion.getConditions();
        assertThat(conditions, notNullValue());
        final DateTime notBefore = conditions.getNotBefore();
        // TODO: The samples the TW boys sent had expired, so an assertion on the after here will cause a failure   
        Date now = new Date();
        assertTrue(notBefore.toDate().before(now));

        // TODO: this isn't the case for the canned encrpyted delivery from TimeWarner
        //assertTrue(notOnOrAfter.toDate().after(now));
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

    @Test
    public void testSignedTWResponse() {
        SAML2Handler handler = new SAML2Handler();
        IOHelper ioHelper = new IOHelper();
        // Get hold of our keystore
        final String keyStorePath = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\serviceKeyStore.jks$");
        // Create a decrypter passing in the path ot the store, the store password and the
        // password required for the private key.
        final AsymmetricalSessionKeySAMLDecrypter decrypter =
                new AsymmetricalSessionKeySAMLDecrypter(keyStorePath, "rmi+ssl", "remoteservice", "remoteservice");
        // Get hold of our test data
        final Response response = getValidSignedTWResponse(handler, ioHelper);



        

        final EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);

        // Decrypt the data they sent
        final Assertion gotAssertion = decrypter.decryptAssertion(encryptedAssertion);

        // TODO: We check the SAML version is valid
        assertThat(gotAssertion.getVersion(), is(SAMLVersion.VERSION_20));
        assertThat(gotAssertion.getIssuer(), notNullValue());

        // TODO: What constitutes a valid issuer?
        assertThat(gotAssertion.getIssuer().getValue(), is("https://twservices.dev.timewarner.com/TWSAMLService"));

        // TODO: What constitues a valid format for the NameID, as it could be many different formats?
        assertThat(gotAssertion.getSubject(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID().getValue(), is("0007058473@tw|9/21/2010 1:53:41 AM@tw"));
        assertTrue(gotAssertion.getSubject().getNameID().getFormat().equals(NameIDType.UNSPECIFIED));

        // TODO: We could even have an SP identifier here to cover the mapping of TWID to MyView identifier if needed
        //final String weCouldUseThis = gotAssertion.getSubject().getNameID().getSPProvidedID();

        // TODO: What consitutes validity for NotBefore and NotOnOrAfter?
        assertThat(gotAssertion.getConditions(), notNullValue());
        final Conditions conditions = gotAssertion.getConditions();
        assertThat(conditions, notNullValue());
        final DateTime notBefore = conditions.getNotBefore();
        // TODO: The samples the TW boys sent had expired, so an assertion on the after here will cause a failure
        Date now = new Date();
        assertTrue(notBefore.toDate().before(now));

        // TODO: this isn't the case for the canned encrpyted delivery from TimeWarner
        //assertTrue(notOnOrAfter.toDate().after(now));
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


    private Response getValidTWResponse(final SAML2Handler handler, final IOHelper ioHelper) {
        // Lets read in our TW Response to validate its content from file that holds the data
        final String responsePath = TestHelper.getFullPath("^.*fixtures\\\\canned_saml\\\\Response\\\\TWResponse_with_encrypted_Authn_assertion.xml$");
        final InputStream responseStream = ioHelper.openFileAsInputStream(responsePath);
        final XMLObject returnedObject = handler.readFromStream(responseStream);
        assertThat(returnedObject, notNullValue());
        assertTrue(returnedObject instanceof Response);
        return (Response) returnedObject;
    }

      private Response getValidSignedTWResponse(final SAML2Handler handler, final IOHelper ioHelper) {
        // Lets read in our TW Response to validate its content from file that holds the data
        final String responsePath = TestHelper.getFullPath("^.*fixtures\\\\canned_saml\\\\Response\\\\TWSignedResponse_with_encrypted_Authn_assertion.xml$");
        final InputStream responseStream = ioHelper.openFileAsInputStream(responsePath);
        final XMLObject returnedObject = handler.readFromStream(responseStream);
        assertThat(returnedObject, notNullValue());
        assertTrue(returnedObject instanceof Response);
        return (Response) returnedObject;
    }
}
