package com.timepoorprogrammer.saml.core;

import com.timepoorprogrammer.saml.core.SAML11Handler;
import org.junit.Test;
import org.opensaml.saml1.core.*;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.Attribute;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml2.core.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class SAML11HandlerTest {

    @Test
    public void testCreateAuthnAssertion() {
        SAML11Handler handler = new SAML11Handler("MC");
        final Subject subject = handler.createSubject("189502", "MC", NameIdentifier.UNSPECIFIED, "bearer");
        final Assertion assertion = handler.createAssertion(subject, 30, 30);
        handler.printToFile(assertion, null);
    }

    @Test
    public void testCreateAuthnAssertion_withAttributes() {
        SAML11Handler handler = new SAML11Handler("MC");
        final Subject subject = handler.createSubject("189502", "MC", NameIdentifier.UNSPECIFIED, "bearer");
        Map<String, String> attributes = new HashMap<String, String>(0);
        attributes.put("securityClearance", "C2");
        attributes.put("roles", "editor,reviewer");
        final Assertion assertion = handler.createAssertion(subject, 30, 30, attributes);
        handler.printToFile(assertion, null);
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        assertThat(attributeStatements.size(), is(1));
        AttributeStatement statement = attributeStatements.get(0);
        List<Attribute> gotAttributes = statement.getAttributes();
        assertThat(attributes.size(), is(2));
        for (Attribute attribute : gotAttributes) {
            handler.printToFile(attribute, null);
        }
    }



    @Test
    public void testCreateResponse() {
        SAML11Handler handler = new SAML11Handler("MC");
        final Subject subject = handler.createSubject("189502", "MC", NameIdentifier.UNSPECIFIED, "bearer");
        final Assertion assertion = handler.createAssertion(subject, 30, 30);
        Response samlResponse = handler.createResponse(StatusCode.SUCCESS, "AccessRequest", null);
        samlResponse.setRecipient("http://ac27010.uk.rebushr.com:8080/SAMLWeb/myview/SAML11AssertionConsumer");
        samlResponse.getAssertions().add(assertion);
        handler.printToFile(samlResponse, null);
    }
}