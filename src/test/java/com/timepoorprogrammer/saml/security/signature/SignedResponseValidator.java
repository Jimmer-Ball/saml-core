package com.timepoorprogrammer.saml.security.signature;

import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.core.SAML2Handler;
import com.timepoorprogrammer.saml.security.encryption.AsymmetricalSessionKeySAMLDecrypter;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;

import com.timepoorprogrammer.saml.security.signature.SAMLSignatureValidator;
import org.joda.time.DateTime;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.List;

/**
 * Separately threaded class for validating a signed response using the usual Unit testing assertion
 * tools.
 *
 * For whatever reason xmlsig signing and verifying should take place in seperate threads (if the
 * signature changes, which may be the case in unit testing).  So, for safety the verification bit
 * goes in its own thread just ot avoid any nastiness which could occur with multiple signatures
 * (so multiple tests in SAMLSignatureCreatorTest).
 *
 * Also, why aren't we using files for creating a signed response, and then picking up a signed
 * response.  Well, transport (serialisation) to file breaks the XML digital signature (at least
 * the way we are doing it does) so the unit tests (see SAMLSignatureCreatorTest) make the
 * SAML objects and sign them, and then keep them in memory (and then pass them onto this, in a
 * seperate thread).
 *
 */
public class SignedResponseValidator implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(SignedResponseValidator.class);
    Response response;

    public SignedResponseValidator(final Response response) {
        this.response = response;
    }

    /**
     * This is a seperate thread for signed response validation as for whatever reason "xmlsec"
     * doesn't like doing creation of a signature, and validation of a signature in the same thread.
     *
     * Note: CoreMatchers don't have to be used in a Test only, they are valid here too.
     */
    public void run() {
        log.info("Inside SignedResponseValidator thread run method");
        SAML2Handler handler = new SAML2Handler();
        // Use the public key of TimeWarner to validate the signature
        final String keyStorePath = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\serviceKeyStore.jks$");
        final SAMLSignatureValidator sigValidator = new SAMLSignatureValidator(keyStorePath, "rmi+ssl", "localclient", "localclient");
        assertTrue(sigValidator.isValid(response));
        log.info("Signature is valid");

        // Show the signed response details in all its glory.
        handler.printToFile(response, null);

        // TODO: Validate response content fields too

        // Get the encrypted Assertion from the response
        final EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);
        if (encryptedAssertion == null) throw new RuntimeException("Missing encrypted assertion");

        // Decrypt the assertion using the Northgate private key
        final AsymmetricalSessionKeySAMLDecrypter decrypter =
                new AsymmetricalSessionKeySAMLDecrypter(keyStorePath, "rmi+ssl", "remoteservice", "remoteservice");
        final Assertion gotAssertion = decrypter.decryptAssertion(encryptedAssertion);
        if (gotAssertion == null) throw new RuntimeException("Assertion is missing");

        // TODO: We check the SAML version is valid
        assertThat(gotAssertion.getVersion(), is(SAMLVersion.VERSION_20));
        log.info(gotAssertion.getVersion().toString());
        assertThat(gotAssertion.getIssuer(), notNullValue());

        // TODO: What constitutes a valid issuer?
        assertThat(gotAssertion.getIssuer().getValue(), is("http://timewarner.com/IDPService"));
        log.info(gotAssertion.getIssuer().toString());
        // TODO: What constitues a valid format for the NameID, as it could be many different formats?
        assertThat(gotAssertion.getSubject(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID().getValue(), is("1895021000"));
        assertTrue(gotAssertion.getSubject().getNameID().getFormat().equals(NameIDType.PERSISTENT));
        log.info(gotAssertion.getSubject().toString());

        // TODO: We could even have an SP identifier here to cover the mapping of TWID to MyView identifier if needed
        //final String weCouldUseThis = gotAssertion.getSubject().getNameID().getSPProvidedID();

        // TODO: What consitutes validity for NotBefore and NotOnOrAfter?
        assertThat(gotAssertion.getConditions(), notNullValue());
        final Conditions conditions = gotAssertion.getConditions();
        assertThat(conditions, notNullValue());
        final DateTime notBefore = conditions.getNotBefore();
        final DateTime notOnOrAfter = conditions.getNotOnOrAfter();
        Date now = new Date();
        assertTrue(notBefore.toDate().before(now));
        assertTrue(notOnOrAfter.toDate().after(now));

        // Process the authentication statements
        final List<AuthnStatement> authnStatements = gotAssertion.getAuthnStatements();
        assertThat(authnStatements, notNullValue());
        assertThat(authnStatements.size(), is(1));
        final AuthnStatement authenticationType = authnStatements.get(0);
        // TODO: What type (if we actually care) should this authentication type be? Note: The nesting on the getAuthContextClassRef, it has a wierd structure eh?
        assertTrue(AuthnContext.PPT_AUTHN_CTX.equals(authenticationType.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef()));

        // TODO: We could even have attribute statements in this that hold the MyView identifier

        // Show the assertion contents
        handler.printToFile(gotAssertion, null);
    }
}
