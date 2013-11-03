package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.core.SAMLResponseValidationResult;
import com.timepoorprogrammer.saml.core.SAMLResponseValidationResult;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Response;

import java.util.Map;

/**
 * SAML 2 response validator interface.
 *
 * @author Jim Ball
 */
public interface SAML2ResponseValidator {
    /**
     * Validate the incoming response relative to the responses already seen in the last X minutes.  You can get free
     * form if you must in your impl, just be careful as SAML is quite strict, so if you are going to implement one of
     * these yourself, you need to known what you are doing from a SAML response processing specification point of view.
     *
     * @param response             response to validate
     * @param responsesAlreadySeen responses already seen
     * @param maxMinutes           The number of minutes we go back in time to see if we've seen a SAML response
     *                             with the same identifier as the identifier provided in the new response.
     * @return SAML response validation results
     */
    SAMLResponseValidationResult validate(Response response, Map<DateTime, String> responsesAlreadySeen, int maxMinutes);
}
