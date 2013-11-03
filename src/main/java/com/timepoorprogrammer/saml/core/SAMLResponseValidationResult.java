package com.timepoorprogrammer.saml.core;

/**
 * Capture the validation results for a SAML response object so they can be reported to higher levels of the
 * application stack to provide meaningful error details to consumer clients.
 *
 * @author Jim Ball
 */
public class SAMLResponseValidationResult {
    private boolean valid;
    private String errorDetails;

    /**
     * Default constructor will result in a positive result until set otherwise
     */
    public SAMLResponseValidationResult() {
        this.valid = true;
    }

    public SAMLResponseValidationResult(boolean valid, String errorDetails) {
        this.valid = valid;
        this.errorDetails = errorDetails;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getErrorDetails() {
        return errorDetails;
    }

    public void setErrorDetails(String errorDetails) {
        this.errorDetails = errorDetails;
    }
}
