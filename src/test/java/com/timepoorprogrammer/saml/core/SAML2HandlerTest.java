package com.timepoorprogrammer.saml.core;

import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.core.IOHelper;
import com.timepoorprogrammer.saml.core.SAML2Handler;
import org.joda.time.DateTime;
import org.junit.Test;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class SAML2HandlerTest {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(SAML2HandlerTest.class);

    @Test
    public void testCreateAuthnAssertion() {
        SAML2Handler handler = new SAML2Handler("NZ");
        final Subject subject = handler.createSubject("189502", NameIdentifier.UNSPECIFIED, "bearer");
        final Assertion assertion = handler.createAuthnAssertion(subject, AuthnContext.PASSWORD_AUTHN_CTX, 30, 30);
        handler.printToFile(assertion, null);
    }

    @Test
    public void testCreateAttributeAssertion() {
        SAML2Handler handler = new SAML2Handler("http://saml.r.us/AssertingParty");
        Subject subject = handler.createSubject("louisdraper@abc.gov", NameID.EMAIL, null);
        Map<String, String> attributes = new HashMap<String, String>(0);
        attributes.put("securityClearance", "C2");
        attributes.put("roles", "editor,reviewer");
        // Print pretty
        handler.printToFile(handler.createAttributeAssertion(subject, attributes), null);
    }

    @Test
    public void testCreateAuthnAssertion_withAttributes() {
        SAML2Handler handler = new SAML2Handler("NZ");
        final Subject subject = handler.createSubject("189502", NameIdentifier.UNSPECIFIED, "bearer");
        Map<String, String> attributes = new HashMap<String, String>(0);
        attributes.put("securityClearance", "C2");
        attributes.put("roles", "editor,reviewer");
        final Assertion assertion = handler.createAuthnAssertion(subject, AuthnContext.PASSWORD_AUTHN_CTX, 30, 30, attributes);

        // Lets have a look at the extra attributes
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        assertThat(attributeStatements.size(), is(1));
        AttributeStatement statement = attributeStatements.get(0);
        List<Attribute> gotAttributes = statement.getAttributes();
        assertThat(attributes.size(), is(2));
        for (Attribute attribute : gotAttributes) {
            handler.printToFile(attribute, null);
        }
    }

    /**
     * Parse the canned PPT_AUTHN_CTX authentication assertion found in module "fixtures", under
     * sub-directory "Assertion" of file name Authn.xml.  This illustrates the
     * validation routines that can and probably should be applied to a simple (lol)
     * inbound Authn assertion.
     */
    @Test
    public void testReadFromStream_cannedAuthAssertion() {
        SAML2Handler handler = new SAML2Handler();
        String pathToAssertion = TestHelper.getFullPath("^.*fixtures\\\\canned_saml\\\\Assertion\\\\Authn.xml$");
        IOHelper ioHelper = new IOHelper();
        final InputStream authAssertionStream = ioHelper.openFileAsInputStream(pathToAssertion);
        final XMLObject returnedObject = handler.readFromStream(authAssertionStream);
        assertThat(returnedObject, notNullValue());
        assertTrue(returnedObject instanceof Assertion);
        final Assertion gotAssertion = (Assertion) returnedObject;
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
    }

    /**
     * Parse the canned TW authentication assertion found in module "fixtures", under
     * sub-directory "Assertion" of file name TWAuthn.xml.  This illustrates the
     * validation routines that can and probably should be applied to a simple Authn assertion.
     */
    @Test
    public void testReadFromStream_cannedTWAuthAssertion() {
        SAML2Handler handler = new SAML2Handler();
        IOHelper ioHelper = new IOHelper();
        String pathToAssertion = TestHelper.getFullPath("^.*fixtures\\\\canned_saml\\\\Assertion\\\\TWAuthn.xml$");
        final InputStream authAssertionStream = ioHelper.openFileAsInputStream(pathToAssertion);
        final XMLObject returnedObject = handler.readFromStream(authAssertionStream);
        assertThat(returnedObject, notNullValue());
        assertTrue(returnedObject instanceof Assertion);
        final Assertion gotAssertion = (Assertion) returnedObject;
        // TODO: We check the SAML version is valid
        assertThat(gotAssertion.getVersion(), is(SAMLVersion.VERSION_20));
        assertThat(gotAssertion.getIssuer(), notNullValue());

        // TODO: What constitutes a valid issuer?
        assertThat(gotAssertion.getIssuer().getValue(), is("https://twservices.dev.timewarner.com/TWSAMLService"));

        // TODO: What constitues a valid format for the NameID, as it could be many different formats?
        assertThat(gotAssertion.getSubject(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID().getValue(), is("TIMEWARNERID|9/20/2010 10:43:03 PM"));
        assertTrue(gotAssertion.getSubject().getNameID().getFormat().equals(NameIDType.UNSPECIFIED));

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
        assertTrue(AuthnContext.PASSWORD_AUTHN_CTX.equals(authenticationType.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef()));

        // TODO: We could even have attribute statements in this that hold the MyView identifier
    }

    /**
     * Read a simple canned attribute statement held in module "fixtures", sub directory canned_saml/Assertion
     * of the name Attribute.xml.  So, a customer can send us attributes effectively.
     * <p/>
     * Note it is possible that these attributes can also come on the authentication assertion (above) as well, as they
     * are a mechanism for holding extra IDP provided attributes about our identity.  So in essence this could
     * hold ALL the application sub-identifiers for an identity within a realm we currently hold in OpenSSO.
     */
    @Test
    public void testReadFromStream_cannedAttributeAssertion() {
        SAML2Handler handler = new SAML2Handler();
        IOHelper ioHelper = new IOHelper();
        String pathToAssertion = TestHelper.getFullPath("^.*fixtures\\\\canned_saml\\\\Assertion\\\\Attribute.xml$");
        final InputStream authAssertionStream = ioHelper.openFileAsInputStream(pathToAssertion);
        final XMLObject returnedObject = handler.readFromStream(authAssertionStream);
        assertThat(returnedObject, notNullValue());
        assertTrue(returnedObject instanceof Assertion);
        final Assertion gotAssertion = (Assertion) returnedObject;
        assertThat(gotAssertion.getVersion(), is(SAMLVersion.VERSION_20));
        assertThat(gotAssertion.getIssuer(), notNullValue());
        assertThat(gotAssertion.getIssuer().getValue(), is("http://mycom.com/MyJavaAttributeService"));
        assertThat(gotAssertion.getSubject(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID().getValue(), is("ga489Slge8+0nio9="));

        // There could be many AttributeStatement blocks within an Assertion, but we are only expecting one block
        final List<AttributeStatement> attributeStatements = gotAssertion.getAttributeStatements();
        assertThat(attributeStatements, notNullValue());
        assertThat(attributeStatements.size(), is(1));
        // There could be many Attributes within a block, and were are expecting two attributes
        final List<Attribute> attributes = attributeStatements.get(0).getAttributes();
        assertThat(attributes, notNullValue());
        assertThat(attributes.size(), is(2));
        final Attribute fullName = attributes.get(0);
        final Attribute jobTitle = attributes.get(1);
        assertThat(fullName.getName(), is("FullName"));
        assertThat(jobTitle.getName(), is("JobTitle"));
        // An attribute can have many values
        final List<XMLObject> nameValues = fullName.getAttributeValues();
        final List<XMLObject> jobValues = jobTitle.getAttributeValues();
        assertThat(nameValues, notNullValue());
        assertThat(jobValues, notNullValue());
        assertThat(nameValues.size(), is(1));
        assertThat(jobValues.size(), is(1));
        // And you get each value via DOM indirection
        assertThat(nameValues.get(0).getDOM().getFirstChild().getTextContent(), is("William Whitford Provost"));
        assertThat(jobValues.get(0).getDOM().getFirstChild().getTextContent(), is("Grand Poobah"));
    }

    /**
     * Read a simple canned authorisation assertion statement.  Authorisation is something that happens in
     * response to an initial request.
     * <p/>
     * This implies our service has had to go back to the IDP and get the user to login, which then results
     * is a redirect back to us with one of these.  So, this could result from an unsolicited attempt to access
     * a resource in the network resulting in an IDP exchange resulting in getting one of these subsequently.
     */
    @Test
    public void testReadFromStream_cannedAuthorisationDecisionAssertion() {
        SAML2Handler handler = new SAML2Handler();
        IOHelper ioHelper = new IOHelper();
        String pathToAssertion = TestHelper.getFullPath("^.*fixtures\\\\canned_saml\\\\Assertion\\\\AuthzDecision.xml$");
        final InputStream authorisationAssertionStream = ioHelper.openFileAsInputStream(pathToAssertion);
        final XMLObject returnedObject = handler.readFromStream(authorisationAssertionStream);
        assertThat(returnedObject, notNullValue());
        assertTrue(returnedObject instanceof Assertion);
        final Assertion gotAssertion = (Assertion) returnedObject;
        assertThat(gotAssertion.getVersion(), is(SAMLVersion.VERSION_20));
        assertThat(gotAssertion.getIssuer(), notNullValue());
        assertThat(gotAssertion.getIssuer().getValue(), is("http://mycom.com/MyJavaAuthorizationService"));
        assertThat(gotAssertion.getSubject(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID(), notNullValue());
        assertThat(gotAssertion.getSubject().getNameID().getValue(), is("ga489Slge8+0nio9="));

        // There could be many Authorisation statements, but we are only expecting one
        final List<AuthzDecisionStatement> authzStatements = gotAssertion.getAuthzDecisionStatements();
        assertThat(authzStatements, notNullValue());
        assertThat(authzStatements.size(), is(1));

        // An authorisation statement is for a resource and has a decision
        assertThat(authzStatements.get(0).getResource(), is("http://mycom.com/Repository/Private"));
        assertThat(authzStatements.get(0).getDecision(), is(DecisionTypeEnumeration.PERMIT));
        log.info("Permission granted to user on resource");

        // For a given authorisation statement, a list of actions may well be provided, and these are
        // free strings so we can build up our own type of authrisation mechanism here. The SAML is
        // just the transport of the information.
        //
        // With our canned example, we know we only have one and its action string value is "read".
        final Action action = authzStatements.get(0).getActions().get(0);
        assertThat(action.getAction(), is("read"));
    }

    @Test
    public void createResponse_cannedForTimeWarner() {
        SAML2Handler handler = new SAML2Handler("http://timewarner.com/IDPService");
        // Create a response indicating its from a requester, setting the basics and the destination
        // note this takes the issuer details used on construction of the SAML handle
        Response response = handler.createResponse(StatusCode.REQUESTER_URI, "AccessRequest", null);
        response.setDestination("http://northgatearinso.com/SDPService");
        handler.printToFile(response, null);
    }
}