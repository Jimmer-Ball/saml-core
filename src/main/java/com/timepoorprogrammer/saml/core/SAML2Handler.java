package com.timepoorprogrammer.saml.core;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.schema.XSAny;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.UUID;

/**
 * SAML2 base handler.
 * <p/>
 * As at 02/09/2010 deals with identity provider initiated single sign on only.
 *
 * @author Jim Ball
 */
public class SAML2Handler extends AbstractSAMLHandler {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(SAML2Handler.class);
    /**
     * Confirmation prefix required for SAML2 subject elements
     */
    private static final String CM_PREFIX = "urn:oasis:names:tc:SAML:2.0:cm:";

    /**
     * Issuer URL
     */
    private String issuerURL;

    /**
     * This is how a consumer would initialise the handler.
     */
    public SAML2Handler() {
        this(null);
    }

    /**
     * This is how a producer would initialise the handler to ensure that
     * all SAML holds the right issuer details.
     *
     * @param issuerURL This will be used in all generated assertions
     */
    public SAML2Handler(String issuerURL) {
        this.issuerURL = issuerURL;
    }

    /**
     * Helper method to spawn a new Issuer element based on our issuer URL.
     *
     * @return Issuer issuer
     */
    public Issuer spawnIssuer() {
        Issuer result = null;
        if (issuerURL != null) {
            result = (Issuer) create(Issuer.DEFAULT_ELEMENT_NAME);
            result.setValue(issuerURL);
            if (matchesEntityFormat(issuerURL)) {
                log.debug("Issuer matches entity format");
                result.setFormat(NameIDType.ENTITY);
            }
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
     * Returns a SAML subject.
     *
     * @param username           The subject name
     * @param format             If non-null, we'll set as the subject name format
     * @param confirmationMethod If non-null, we'll create a SubjectConfirmation
     *                           element and use this as the Method attribute; must be "sender-vouches"
     *                           or "bearer", as HOK would require additional parameters and so is NYI
     * @return SAML subject
     */
    public Subject createSubject(String username, String format, String confirmationMethod) {
        NameID nameID = (NameID) create(NameID.DEFAULT_ELEMENT_NAME);
        nameID.setValue(username);
        if (format != null) {
            nameID.setFormat(format);
        }
        Subject subject = (Subject) create(Subject.DEFAULT_ELEMENT_NAME);
        subject.setNameID(nameID);
        if (confirmationMethod != null) {
            SubjectConfirmation confirmation = (SubjectConfirmation) create(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
            confirmation.setMethod(CM_PREFIX + confirmationMethod);
            subject.getSubjectConfirmations().add(confirmation);
        }
        return subject;
    }

    /**
     * Returns a SAML subject.
     *
     * @param username           The subject name
     * @param format             If non-null, we'll set as the subject name format
     * @param confirmationMethod If non-null, we'll create a SubjectConfirmation
     *                           element and use this as the Method attribute; must be "sender-vouches"
     *                           or "bearer", as HOK would require additional parameters and so is NYI
     * @param recipientURL       The recipient details.  This is required for any google apps interaction in that
     *                           google needs this to be included and google needs it to be the same as the intended
     *                           service provider URL (which is obtained from metadata).
     * @param timeToLive         time to live in minutes
     * @return SAML subject
     */
    public Subject createSubject(String username, String format, String confirmationMethod, String recipientURL, int timeToLive) {
        NameID nameID = (NameID) create(NameID.DEFAULT_ELEMENT_NAME);
        nameID.setValue(username);
        if (format != null) {
            nameID.setFormat(format);
        }
        Subject subject = (Subject) create(Subject.DEFAULT_ELEMENT_NAME);
        subject.setNameID(nameID);
        if (confirmationMethod != null) {
            SubjectConfirmation confirmation = (SubjectConfirmation) create(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
            confirmation.setMethod(CM_PREFIX + confirmationMethod);
            SubjectConfirmationData confirmationData = (SubjectConfirmationData) create(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
            confirmationData.setRecipient(recipientURL);
            DateTime now = new DateTime();
            confirmationData.setNotOnOrAfter(now.plusMinutes(timeToLive));
            confirmation.setSubjectConfirmationData(confirmationData);
            subject.getSubjectConfirmations().add(confirmation);
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
     * Returns a SAML assertion with generated ID, current timestamp, given
     * subject, and with simple time-based conditions passed in for variety in
     * time to live and don't process before.
     *
     * @param subject    Subject of the assertion
     * @param before     before time in seconds
     * @param timeToLive maximum amount of time in minutes to live for this assertion
     * @return assertion
     */
    public Assertion createAssertion(Subject subject, final int before, final int timeToLive) {
        Assertion assertion = (Assertion) create(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.setID(UUID.randomUUID().toString());
        DateTime now = new DateTime();
        assertion.setIssueInstant(now);
        if (issuerURL != null) {
            assertion.setIssuer(spawnIssuer());
        }
        assertion.setSubject(subject);
        Conditions conditions = (Conditions) create(Conditions.DEFAULT_ELEMENT_NAME);
        conditions.setNotBefore(now.minusSeconds(before));
        conditions.setNotOnOrAfter(now.plusMinutes(timeToLive));
        assertion.setConditions(conditions);
        return assertion;
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
     * @param statusCode   status code
     * @param inResponseTo in response to
     * @return SAML response
     */
    public Response createResponse(String statusCode, String inResponseTo) {
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
    public Response createResponse(String statusCode, String message, String inResponseTo) {
        try {
            Response response = (Response) create(Response.DEFAULT_ELEMENT_NAME);
            response.setID(UUID.randomUUID().toString());
            if (inResponseTo != null) {
                response.setInResponseTo(inResponseTo);
            }
            DateTime now = new DateTime();
            response.setIssueInstant(now);
            if (issuerURL != null) {
                response.setIssuer(spawnIssuer());
            }
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
        Response response = createResponse(StatusCode.SUCCESS_URI, inResponseTo);
        response.getAssertions().add(assertion);
        return response;
    }

    /**
     * Returns a SAML authentication assertion.
     *
     * @param subject             The subject of the assertion
     * @param authnCtx            The "authentication context class reference",
     *                            e.g. AuthnContext.PPT_AUTHN_CTX
     * @param timeBeforeInSeconds pre generation validity
     * @param timeAfterInMinutes  post generation validity
     * @return Authentication assertion
     */
    public Assertion createAuthnAssertion(Subject subject, String authnCtx, int timeBeforeInSeconds, int timeAfterInMinutes) {
        Assertion assertion = createAssertion(subject, timeBeforeInSeconds, timeAfterInMinutes);
        AuthnContextClassRef ref = (AuthnContextClassRef) create(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        ref.setAuthnContextClassRef(authnCtx);
        AuthnContext authnContext = (AuthnContext) create(AuthnContext.DEFAULT_ELEMENT_NAME);
        authnContext.setAuthnContextClassRef(ref);
        AuthnStatement authnStatement = (AuthnStatement) create(AuthnStatement.DEFAULT_ELEMENT_NAME);
        authnStatement.setAuthnContext(authnContext);
        authnStatement.setAuthnInstant(new DateTime());
        assertion.getStatements().add(authnStatement);
        return assertion;
    }

    /**
     * Create an assertion with extra attributes.  Attributes are used by the destination end point to make access
     * control decisions. In English, we can put stuff like what "role" is the user as an attribute key value pair of
     * say "role", "engineer" .
     *
     * @param subject             The subject of the assertion (who is it "for")
     * @param authnCtx            The "authentication context class reference",
     *                            e.g. AuthnContext.PPT_AUTHN_CTX
     * @param timeBeforeInSeconds pre generation validity
     * @param timeAfterInMinutes  post generation validity
     * @param attributes          extra attributes to add to the assertion may be null
     * @return Authentication assertion with extra attributes
     */
    public Assertion createAuthnAssertion(Subject subject, String authnCtx, int timeBeforeInSeconds, int timeAfterInMinutes,
                                          Map<String, String> attributes) {
        Assertion assertion = createAssertion(subject, timeBeforeInSeconds, timeAfterInMinutes);
        AuthnContextClassRef ref = (AuthnContextClassRef) create(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        ref.setAuthnContextClassRef(authnCtx);
        AuthnContext authnContext = (AuthnContext) create(AuthnContext.DEFAULT_ELEMENT_NAME);
        authnContext.setAuthnContextClassRef(ref);
        AuthnStatement authnStatement = (AuthnStatement) create(AuthnStatement.DEFAULT_ELEMENT_NAME);
        authnStatement.setAuthnContext(authnContext);
        authnStatement.setAuthnInstant(new DateTime());
        assertion.getStatements().add(authnStatement);

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
     * Adds a SAML attribute to an input attribute statement.
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
        attribute.setName(name);
        attribute.getAttributeValues().add(valueElement);
        statement.getAttributes().add(attribute);
    }

    /**
     * Returns a SAML attribute assertion.
     *
     * @param subject    Subject of the assertion
     * @param attributes Attributes to be stated (may be null)
     * @return attribute Assertion
     */
    public Assertion createAttributeAssertion(Subject subject, Map<String, String> attributes) {
        Assertion assertion = createAssertion(subject);
        AttributeStatement statement = (AttributeStatement) create(AttributeStatement.DEFAULT_ELEMENT_NAME);
        if (attributes != null) {
            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                addAttribute(statement, entry.getKey(), entry.getValue());
            }
        }
        assertion.getStatements().add(statement);
        return assertion;
    }

    /**
     * If the issuer string matches the SAML entity format, then we need to set the type of the
     * Issuer details ino outbound assertions and response bodys to entity, as otherwise in SAML2
     * on receptino at the far end service, the default behaviour (without a format) is to treat
     * the issuer details as unspecified, so not necessarily relating to SAML metadata.
     *
     * @param issuer issuer string
     * @return true if in
     */
    private boolean matchesEntityFormat(final String issuer) {
        if (issuer != null) {
            boolean matchesEntityFormat = false;
            if (issuer.startsWith("http://") || issuer.startsWith("https://")) {
                matchesEntityFormat = true;
            }
            return matchesEntityFormat;
        } else {
            final String errorMessage = "Cannot determine the format of a null issuer string";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }
}
