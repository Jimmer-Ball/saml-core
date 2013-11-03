package com.timepoorprogrammer.saml.impls.standard.consumer.processor;

import com.timepoorprogrammer.saml.common.AuditMessages;
import com.timepoorprogrammer.saml.core.SAMLResponseValidationResult;
import com.timepoorprogrammer.saml.impls.SAML11ResponseValidator;
import com.timepoorprogrammer.saml.common.AuditMessages;
import org.joda.time.DateTime;
import org.opensaml.saml1.core.Response;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Standard SAML1.1 response validator that prevents SAML response replay attacks where the same identifier is provided
 * for a SAML response as has already been seen in the past maxMinutes.
 * <p/>
 * If you need a special one of these for a given customer or service then provide one in the right place and ensure
 * the SAML11AssertionConsumerProcessor implementation you are using picks up its validator via the
 * SAML11ResponseValidatorFactory class.
 *
 * @author Jim Ball
 */
public class SAML11ResponseValidatorImpl implements SAML11ResponseValidator {

    @Override
    public SAMLResponseValidationResult validate(Response response,
                                                 Map<DateTime, String> responsesAlreadySeen,
                                                 int maxMinutes) {
        SAMLResponseValidationResult result = new SAMLResponseValidationResult();
        try {
            // Remove any "old" request identifiers, older than maxMinutes from our responsesAlreadySeen as we do not
            // want the "queue" of responses the processor has already seen to grow and grow uncontrollably.
            final DateTime now = new DateTime();
            List<DateTime> keysToRemove = new ArrayList<DateTime>(0);
            Set<DateTime> keys = responsesAlreadySeen.keySet();
            for (DateTime key : keys) {
                if (key.plusMinutes(maxMinutes).isBefore(now)) {
                    keysToRemove.add(key);
                }
            }
            for (DateTime removeMe : keysToRemove) {
                responsesAlreadySeen.remove(removeMe);
            }
            // See if the responses already seen in the last maxMinutes already hold an identifier that is the same
            // as the identifier of the response being processed, and if not, add the response ID
            final String responseId = response.getID();
            if (responsesAlreadySeen.containsValue(responseId)) {
                result.setErrorDetails(String.format(AuditMessages.ConsumerCode.CONSUMER_RESPONSE_REPLAY_ERROR.getDetailsPattern(),
                        response.getID(), maxMinutes));
                result.setValid(false);
            } else {
                responsesAlreadySeen.put(now, responseId);
                result.setValid(true);
            }
        } catch (Exception anyE) {
            result.setValid(false);
            result.setErrorDetails("Unexpected exception validating SAML response: " + anyE.getMessage());
        }
        return result;
    }
}
