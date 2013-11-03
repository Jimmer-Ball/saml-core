package com.timepoorprogrammer.saml.security.encryption;

import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.core.SAML2Handler;
import com.timepoorprogrammer.saml.security.encryption.AsymmetricalSessionKeySAMLEncrypter;
import org.junit.Test;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.*;

public class AsymmetricalSessionKeySAMLEncrypterTest {
    @Test
    public void testEncryptAssertion() {
        SAML2Handler handler = new SAML2Handler("MC");
        final String keyStorePath = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\clientKeyStore.jks$");
        final AsymmetricalSessionKeySAMLEncrypter encrypter =
                new AsymmetricalSessionKeySAMLEncrypter(keyStorePath, "rmi+ssl", "remoteservice");
        final Assertion gotAssertion = getValidAuthenticationAssertion(handler);
        final EncryptedAssertion encryptedAssertion = encrypter.encryptAssertion(gotAssertion);

        Response samlResponse = handler.createResponse(StatusCode.SUCCESS_URI, "AccessRequest", null);
        samlResponse.setDestination("http://ac27010.uk.rebushr.com:8080/SAMLWeb/myview/SAML2AssertionConsumer");
        samlResponse.getEncryptedAssertions().add(encryptedAssertion);
        handler.printToFile(samlResponse, null);
    }

    /**
     * Go look at the sample un-encoded SAML Authentication assertion in fixtures/canned_saml/Assertion
     *
     * @param handler SAML handler
     * @return assertion
     */
    private Assertion getValidAuthenticationAssertion(final SAML2Handler handler) {
        final Subject subject = handler.createSubject("189502", NameIdentifier.UNSPECIFIED, "bearer");
        return handler.createAuthnAssertion(subject, AuthnContext.PASSWORD_AUTHN_CTX, 30, 30);
    }
}
