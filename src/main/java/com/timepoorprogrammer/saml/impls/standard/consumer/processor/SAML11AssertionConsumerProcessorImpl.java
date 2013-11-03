package com.timepoorprogrammer.saml.impls.standard.consumer.processor;

import com.timepoorprogrammer.saml.core.SAMLAssertionValidationResult;
import com.timepoorprogrammer.saml.core.SAMLResponseValidationResult;
import com.timepoorprogrammer.saml.impls.*;
import org.joda.time.DateTime;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml2.metadata.provider.MetadataProvider;

import java.util.HashMap;
import java.util.Map;

/**
 * Default SAML1.1 assertion consumer processor.
 *
 * @author Jim Ball
 */
public class SAML11AssertionConsumerProcessorImpl extends SAMLAssertionConsumerProcessorBase implements SAML11AssertionConsumerProcessor {
    /**
     * Number of minutes within which we look for incoming SAML response bodies with an identifier we've already processed
     */
    private static final int MAX_MINUTES = 30;

    /**
     * The map of responses already seen within the last MAX_MINUTES
     */
    private static Map<DateTime, String> SEEN_RESPONSE_IDS = new HashMap<DateTime, String>(0);

    /**
     * Lock for checking whether we've seen the same SAML response body within the last MAX_MINUTES or not
     */
    private static final Object LOCK = new Object();

    /**
     * Response validator
     */
    private SAML11ResponseValidator responseValidator = null;

    /**
     * Assertion validator
     */
    private SAML11AssertionValidator assertionValidator = null;

    /**
     * Construct a SAML1.1 assertion consumer
     *
     * @param metaDataFilePath metadata file path
     * @param idpId            identity provider SAML entity identifier
     * @param customerCode     identity provider Northgate internal customer code
     * @param idpProtocol      identity provider SAML protocol to use
     * @param spId             service provider id
     * @param mdHandler        metadata handler
     */
    public SAML11AssertionConsumerProcessorImpl(final String metaDataFilePath,
                                                final String idpId,
                                                final String customerCode,
                                                final String idpProtocol,
                                                final String spId,
                                                final MetaDataHandler mdHandler) {
        super(metaDataFilePath, idpId, customerCode, idpProtocol, spId, mdHandler);
        this.responseValidator = SAML11ResponseValidatorFactory.getInstance(customerCode);
        this.assertionValidator = SAML11AssertionValidatorFactory.getInstance(customerCode);
    }

    /**
     * Construct a SAML1.1 assertion consumer
     *
     * @param mdProvider   metadata provider
     * @param idpId        identity provider SAML entity identifier
     * @param customerCode identity provider Northgate internal customer code
     * @param idpProtocol  identity provider SAML protocol to use
     * @param spId         service provider id
     * @param mdHandler    metadata handler
     */
    public SAML11AssertionConsumerProcessorImpl(final MetadataProvider mdProvider,
                                                final String idpId,
                                                final String customerCode,
                                                final String idpProtocol,
                                                final String spId,
                                                final MetaDataHandler mdHandler) {
        super(mdProvider, idpId, customerCode, idpProtocol, spId, mdHandler);
        this.responseValidator = SAML11ResponseValidatorFactory.getInstance(customerCode);
        this.assertionValidator = SAML11AssertionValidatorFactory.getInstance(customerCode);
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML11AssertionConsumerProcessor#auditError(String, String)
     */
    public void auditError(String code, String details) {
        auditMessenger.auditError(code, idpId, idpProtocol, spId, details);
    }

    /**
     * @see SAML11AssertionConsumerProcessor#auditError(String, String)
     */
    public void auditSuccess(String code, String details) {
        auditMessenger.auditSuccess(code, idpId, idpProtocol, spId, details);
    }

    /**
     * @see SAML11AssertionConsumerProcessor#validate(org.opensaml.saml1.core.Response)
     */
    public SAMLResponseValidationResult validate(Response response) {
        synchronized (LOCK) {
            return responseValidator.validate(response, SEEN_RESPONSE_IDS, MAX_MINUTES);
        }
    }

    /**
     * @see SAML11AssertionConsumerProcessor#validate(org.opensaml.saml1.core.Assertion, String)
     */
    public SAMLAssertionValidationResult validate(Assertion assertion, String issuer) {
        return assertionValidator.validate(assertion, issuer);
    }
}