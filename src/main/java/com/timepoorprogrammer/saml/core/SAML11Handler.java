package com.timepoorprogrammer.saml.core;


import org.joda.time.DateTime;
import org.opensaml.saml1.core.*;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.schema.XSAny;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.namespace.QName;
import java.util.Map;
import java.util.UUID;

/**
 * SAML1.1 base handler.
 * <p/>
 * As at 02/09/2010 deals with identity provider initiated web single sign on only.
 *
 * @author Jim Ball
 */
public class SAML11Handler extends AbstractSAMLHandler {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(SAML11Handler.class);

    private static final String DEFAULT_AUTH_METHOD = "urn:oasis:names:tc:SAML:1.0:am:password";

    private static final String CM_PREFIX = "urn:oasis:names:tc:SAML:1.0:cm:";

    /**
     * Issuer URL
     */
    private String issuerURL;


    /**
     * This is how a consumer would initialise the library.
     */
    public SAML11Handler() {
        this(null);
    }

    /**
     * This is how a producer would initialise the library to ensure
     * any SAML it sends our has the right issuer details.
     *
     * @param issuerURL This will be used in all generated assertions
     */
    public SAML11Handler(String issuerURL) {
        this.issuerURL = issuerURL;
    }

    /**
     * Helper method to spawn a new Issuer element based on our issuer URL.
     * <p/>
     * In SAML 1.1, the issuer is just a string, not a first class object
     *
     * @return Issuer issuer
     */
    public String spawnIssuer() {
        String result = null;
        if (issuerURL != null) {
            result = issuerURL;
        }
        return result;
    }

    /**
     * The issuer details can't always be set on construction, and may well
     * need to be overridden.
     *
     * @param issuer issuer details
     */
    public void setIssuer(final String issuer) {
        this.issuerURL = issuer;
    }

    /**
     * Returns a SAML1.1 subject.
     * <p/>
     * <saml:Subject>
     * <saml:NameIdentifier NameQualifier="timewarner.com" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">
     * uid=jimbo
     * </saml:NameIdentifier>
     * <saml:SubjectConfirmation>
     * <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
     * </saml:SubjectConfirmation>
     * </saml:Subject>
     *
     * @param username           The subject name
     * @param sourceDomain       The domain from whence this subject came, for namespacing clarity (if needed)
     * @param format             If non-null, we'll set as the subject name format
     * @param confirmationMethod If non-null, we'll create a SubjectConfirmation
     *                           element and use this as the Method attribute; must be "sender-vouches"
     *                           or "bearer", as HOK would require additional parameters and so is NYI
     * @return SAML subject
     */
    public Subject createSubject(String username, String sourceDomain, String format, String confirmationMethod) {
        Subject subject = (Subject) create(Subject.DEFAULT_ELEMENT_NAME);
        NameIdentifier nameIdentifier = (NameIdentifier) create(NameIdentifier.DEFAULT_ELEMENT_NAME);
        if (sourceDomain != null) {
            nameIdentifier.setNameQualifier(sourceDomain);
        }
        nameIdentifier.setFormat(format);
        nameIdentifier.setNameIdentifier(username);
        subject.setNameIdentifier(nameIdentifier);
        if (confirmationMethod != null) {
            SubjectConfirmation confirmation = (SubjectConfirmation) create(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
            ConfirmationMethod method = (ConfirmationMethod) create(ConfirmationMethod.DEFAULT_ELEMENT_NAME);
            method.setConfirmationMethod(CM_PREFIX + confirmationMethod);
            confirmation.setSubjectConfirmationData(method);
            subject.setSubjectConfirmation(confirmation);
        }
        return subject;
    }

    /**
     * Returns a SAML assertion with a generated ID, current timestamp, given
     * subject, and simple time-based conditions.
     *
     * @param subject Subject of the assertion
     * @return assertion
     */
    public Assertion createAssertion(Subject subject) {
        return createAssertion(subject, DEFAULT_BEFORE_SECONDS, DEFAULT_TIME_TO_LIVE);
    }

    /**
     * Returns a SAML1.1 assertion with generated ID, current timestamp, given
     * subject, and with simple time-based conditions passed in for variety in
     * time to live and don't process before.
     * <p/>
     * Note, the syntax for a SAML1.1 assertion is like so:
     * <p/>
     * <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"
     * MajorVersion="1" MinorVersion="1"
     * AssertionID="buGxcG4gILg5NlocyLccDz6iXrUa"
     * Issuer="www.acompany.com"
     * IssueInstant="2002-06-19T17:05:37.795Z">
     * <saml:Conditions NotBefore="2002-06-19T17:00:37.795Z" NotOnOrAfter="2002-06-19T17:10:37.795Z"/>
     * <saml:AuthenticationStatement
     * AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password"
     * AuthenticationInstant="2002-06-19T17:05:17.706Z">
     * <saml:Subject>
     * <saml:NameIdentifier NameQualifier="timewarner.com" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">
     * uid=jimbo
     * </saml:NameIdentifier>
     * <saml:SubjectConfirmation>
     * <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
     * </saml:SubjectConfirmation>
     * </saml:Subject>
     * </saml:AuthenticationStatement>
     * </saml:Assertion>
     *
     * @param subject    SAML1.1 subject
     * @param before     before time in seconds
     * @param timeToLive maximum amount of time in minutes to live for this assertion
     * @return assertion
     */
    public Assertion createAssertion(final Subject subject, final int before, final int timeToLive) {
        Assertion assertion = (Assertion) create(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.setID(UUID.randomUUID().toString());
        DateTime now = new DateTime();
        assertion.setIssueInstant(now);
        if (issuerURL != null) {
            assertion.setIssuer(spawnIssuer());
        }
        Conditions conditions = (Conditions) create(Conditions.DEFAULT_ELEMENT_NAME);
        conditions.setNotBefore(now.minusSeconds(before));
        conditions.setNotOnOrAfter(now.plusMinutes(timeToLive));
        assertion.setConditions(conditions);
        AuthenticationStatement authStatement = (AuthenticationStatement) create(AuthenticationStatement.DEFAULT_ELEMENT_NAME);
        authStatement.setAuthenticationMethod(DEFAULT_AUTH_METHOD);
        authStatement.setAuthenticationInstant(now);
        authStatement.setSubject(subject);
        assertion.getAuthenticationStatements().add(authStatement);
        return assertion;
    }

    /**
     * Returns a SAML1.1 assertion with generated ID, current timestamp, given
     * subject, and with simple time-based conditions passed in for variety in
     * time to live and don't process before.  Also provide extra attributes for the
     * end point.  Attributes are used by the destination end point to make access
     * control decisions. In English, we can put stuff like what "role" is the user
     * as an attribute key value pair of say "role", "engineer" .
     *
     * @param subject    SAML1.1 subject
     * @param before     before time in seconds
     * @param timeToLive maximum amount of time in minutes to live for this assertion
     * @param attributes attributes to add to the assertion may be null
     * @return assertion
     */
    public Assertion createAssertion(final Subject subject, final int before, final int timeToLive,
                                     Map<String, String> attributes) {
        Assertion assertion = (Assertion) create(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.setID(UUID.randomUUID().toString());
        DateTime now = new DateTime();
        assertion.setIssueInstant(now);
        if (issuerURL != null) {
            assertion.setIssuer(spawnIssuer());
        }
        Conditions conditions = (Conditions) create(Conditions.DEFAULT_ELEMENT_NAME);
        conditions.setNotBefore(now.minusSeconds(before));
        conditions.setNotOnOrAfter(now.plusMinutes(timeToLive));
        assertion.setConditions(conditions);

        AuthenticationStatement authStatement = (AuthenticationStatement) create(AuthenticationStatement.DEFAULT_ELEMENT_NAME);
        authStatement.setAuthenticationMethod(DEFAULT_AUTH_METHOD);
        authStatement.setAuthenticationInstant(now);
        authStatement.setSubject(subject);
        assertion.getAuthenticationStatements().add(authStatement);

        if (attributes != null) {
            AttributeStatement statement = (AttributeStatement) create(AttributeStatement.DEFAULT_ELEMENT_NAME);
            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                addAttribute(statement, entry.getKey(), entry.getValue());
            }
            assertion.getStatements().add(statement);
        }
        return assertion;
    }

    /**
     * Adds a SAML attribute to an attribute statement.
     *
     * @param statement Existing attribute statement
     * @param name      Attribute name
     * @param value     Attribute value
     */
    public void addAttribute(AttributeStatement statement, String name, String value) {
        // Build attribute values as XMLObjects;
        final XMLObjectBuilder builder = Configuration.getBuilderFactory().getBuilder(XSAny.TYPE_NAME);
        XSAny valueElement = (XSAny) builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
        valueElement.setTextContent(value);
        Attribute attribute = (Attribute) create(Attribute.DEFAULT_ELEMENT_NAME);
        attribute.setAttributeName(name);
        attribute.getAttributeValues().add(valueElement);
        statement.getAttributes().add(attribute);
    }

    /**
     * Create a SAML response holding a pre-built assertion
     *
     * @param assertion assertion
     * @return SAML response
     */
    public Response createResponse(Assertion assertion) {
        return createResponse(assertion, null);
    }

    /**
     * Helper method to generate a shell response with a given status code
     * and query ID.
     *
     * @param statusCode   status code so StatusCode.SUCCESS
     * @param inResponseTo in response to
     * @return SAML response
     */
    public Response createResponse(QName statusCode, String inResponseTo) {
        return createResponse(statusCode, null, inResponseTo);
    }

    /**
     * Helper method to generate a shell response with a given status code,
     * status message, and query ID.
     *
     * @param statusCode   status code
     * @param message      message
     * @param inResponseTo in response to
     * @return SAML response
     */
    public Response createResponse(QName statusCode, String message, String inResponseTo) {
        try {
            Response response = (Response) create(Response.DEFAULT_ELEMENT_NAME);
            response.setID(UUID.randomUUID().toString());
            if (inResponseTo != null) {
                response.setInResponseTo(inResponseTo);
            }
            DateTime now = new DateTime();
            response.setIssueInstant(now);

            StatusCode statusCodeElement = (StatusCode) create(StatusCode.DEFAULT_ELEMENT_NAME);
            statusCodeElement.setValue(statusCode);
            Status status = (Status) create(Status.DEFAULT_ELEMENT_NAME);
            status.setStatusCode(statusCodeElement);
            response.setStatus(status);
            if (message != null) {
                StatusMessage statusMessage = (StatusMessage) create(StatusMessage.DEFAULT_ELEMENT_NAME);
                statusMessage.setMessage(message);
                status.setStatusMessage(statusMessage);
            }
            return response;
        } catch (Exception anyE) {
            final String errorMessage = "Error creating SAML response";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Helper method to generate a response, based on a pre-built assertion
     * and query ID.
     *
     * @param assertion    assertion
     * @param inResponseTo in response to
     * @return SAML response
     */
    public Response createResponse(Assertion assertion, String inResponseTo) {
        Response response = createResponse(StatusCode.SUCCESS, inResponseTo);
        response.getAssertions().add(assertion);
        return response;
    }
}