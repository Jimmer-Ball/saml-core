package com.timepoorprogrammer.saml.security.signature;

import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.core.SAML2Handler;
import com.timepoorprogrammer.saml.security.encryption.AsymmetricalSessionKeySAMLEncrypter;
import com.timepoorprogrammer.saml.security.signature.X509SAMLSignatureCreator;
import org.junit.Test;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SAMLSignatureCreator Tester.
 *
 * @author JBall
 */
public class SAMLSignatureCreatorTest {
    private static final Logger log = LoggerFactory.getLogger(SAMLSignatureCreatorTest.class);

    /**
     * Test the flow for creating a signed response holding an encrypted assertion.
     */
    @Test
    public void testGetSignature_createSignedResponseWithEncryptedAssertion() {
        SAML2Handler handler = new SAML2Handler("http://timewarner.com/IDPService");
        final String keyStorePath = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\clientKeyStore.jks$");

        // Create assertion with a TWID
        final Subject subject = handler.createSubject("1895021000", NameIDType.PERSISTENT, "sender-vouches");
        final Assertion assertion = handler.createAuthnAssertion(subject, AuthnContext.PPT_AUTHN_CTX, 30, 600000);

        // Encrypt assertion with Northgate's remoteservice public key, knowing the keystore password and key alias
        final AsymmetricalSessionKeySAMLEncrypter encrypter = new AsymmetricalSessionKeySAMLEncrypter(keyStorePath,
                "rmi+ssl", "remoteservice");
        final EncryptedAssertion encryptedAssertion = encrypter.encryptAssertion(assertion);

        // Create a response indicating its from a requester, setting the basics and the destination
        // note this takes the issuer details used on construction of the SAML handle
        Response response = handler.createResponse(StatusCode.REQUESTER_URI, "AccessRequest", null);
        response.setDestination("http://northgatearinso.com/SDPService");

        // Add our encrypted assertion to our response
        response.getEncryptedAssertions().add(encryptedAssertion);

        // Create our signature using the local private key
        final X509SAMLSignatureCreator sigCreator = new X509SAMLSignatureCreator(keyStorePath, "rmi+ssl");
        Signature signature = (Signature) handler.create(Signature.DEFAULT_ELEMENT_NAME);
        sigCreator.finishSignature(signature, "localclient", "localclient");

        // Add it to the response
        response.setSignature(signature);

        // Finally sign our response with our signature
        try {
            Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);
            Signer.signObject(signature);
            log.info("Created a signed response holding an encrypted assertion");
            // Create the validation thread supplying it with the runnable object, which has access to
            // the signed response we've just created. For whatever reason, signatures cannot be
            // created and checked within the same thread.
            Thread thread = new Thread(new SignedResponseValidator(response));
            thread.start();
            log.info("Joining other testing thread");
            thread.join();
        } catch (Exception anyE) {
            final String errorMessage = "Error signing response and writing object to memory";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }
}
