package com.timepoorprogrammer.saml.common;

/**
 * Assertion consumer and producer message codes and their format for SAML assertion consumers and producers as written
 * out by the SAML middle-ware any any other producer or consumer of SAML who needs to adhere to a standard set of
 * error messages.
 * <p/>
 * Doing it like this means there is one place in all the code to amend the auditing codes and messages returned
 * to the customer infrastructure and written out to the auditing logs at the middle-ware or locally.
 *
 * @author Jim Ball
 */
public class AuditMessages {
    /**
     * Enumeration for the different types of consumer messages.  These are middleware system wide messages and
     * are NOT subject to internationalisation.  They are our messages, not a customers.
     */
    public enum ConsumerCode {
        CONSUMER_INIT_ERROR("Error initialising consumer servlet"),
        CONSUMER_HTTP_TYPE_ERROR("HTTP GET requests are not processed in a SAMLAssertionConsumer"),
        CONSUMER_CONTENT_ERROR("General error reading SAML content out from HTTP POST request, rejecting request"),
        CONSUMER_RESPONSE_CONTENT_ERROR("SAML Response content provided is invalid, rejecting request"),
        CONSUMER_RESPONSE_REPLAY_ERROR("We have already seen the responseId %s in the past %s, not processing this response to avoid denial of service"),
        CONSUMER_SIGNATURE_ERROR("SAML Response signature is invalid, SAML Response has been touched in transit, rejecting request"),
        CONSUMER_DECRYPTION_ERROR("Error decrypting assertion: %s, rejecting request"),
        CONSUMER_EXPECTED_ENCRYPTED_ASSERTION_ERROR("We were expecting an encrypted assertion and never got one, rejecting request"),
        CONSUMER_INVALID_ASSERTION_ERROR("Invalid assertion contents, rejecting request"),
        CONSUMER_ASSERTION_MISSING_SUBJECT_ERROR("SAML assertion is missing a subject or user identifier we can apply, rejecting request"),
        CONSUMER_ASSERTION_INVALID_TIMEFRAME_ERROR("SAML assertion timeframe for usage is invalid, either we are too early, or this assertion has expired"),
        CONSUMER_ASSERTION_MISSING_TIMEFRAME_ERROR("SAML assertion is missing temporal conditions, rejecting request"),
        CONSUMER_ASSERTION_ISSUER_ERROR("SAML assertion is missing Issuer details or issuer details are incorrect, rejecting request"),
        CONSUMER_ASSERTION_VERSION_ERROR("SAML assertion is in a version we cannot cope with, rejecting request"),
        CONSUMER_SUCCESS("Received a valid assertion for user %s, and the target application %s Authoriser implementation at %s has told us this user is authorised to see module %s, so now redirecting browser to backdoor at %s"),
        CONSUMER_REMOTE_APP_ERROR("Error, user %s cannot login at remote application %s according to Authoriser implementation, with following error: %s"),
        CONSUMER_MISSING_ASSERTION_ERROR("Payload is missing expected assertion, cannot establish issuer details, rejecting request ");

        private String detailsPattern;

        ConsumerCode(final String detailsPattern) {
            this.detailsPattern = detailsPattern;
        }

        public String getDetailsPattern() {
            return detailsPattern;
        }
    }

    /**
     * Enumeration for the different types of producer messages.  These are middleware system wide messages and
     * are NOT subject to internationalisation.  They are our messages, not a customers.
     */
    public enum ProducerCode {

        PRODUCER_INIT_ERROR("Error initialising producer servlet"),
        PRODUCER_HTTP_TYPE_ERROR("HTTP GET requests are not processed in a SAMLAssertionProducer"),
        PRODUCER_MISSING_IDENTIFIER_ERROR("Missing expected user identifier"),
        PRODUCER_GENERIC_ERROR("Error creating SAML response and assertion content: "),
        PRODUCER_SUCCESS("Created assertion for user %s, sending to destination %s at service provider %s"),
        PRODUCER_MISSING_CONTEXT_ERROR("Missing expected request parameters from POST context"),
        PRODUCER_MISSING_SIGNING_CERTIFICATE("No applicable signature defined in metadata, but we have to sign a SAML response as an assertion producer");

        private String detailsPattern;

        ProducerCode(final String detailsPattern) {
            this.detailsPattern = detailsPattern;
        }

        public String getDetailsPattern() {
            return detailsPattern;
        }
    }
}
