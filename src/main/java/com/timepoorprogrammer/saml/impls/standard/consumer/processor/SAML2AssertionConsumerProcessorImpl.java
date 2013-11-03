package com.timepoorprogrammer.saml.impls.standard.consumer.processor;

import com.timepoorprogrammer.saml.core.SAMLAssertionValidationResult;
import com.timepoorprogrammer.saml.core.SAMLHelper;
import com.timepoorprogrammer.saml.core.SAMLResponseValidationResult;
import com.timepoorprogrammer.saml.impls.*;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.metadata.provider.MetadataProvider;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Default SAML2 assertion consumer processor.
 *
 * @author Jim Ball
 */
public class SAML2AssertionConsumerProcessorImpl extends SAMLAssertionConsumerProcessorBase implements SAML2AssertionConsumerProcessor {
    /**
     * Only SAML2 does decryption of encrypted assertions
     */
    private Decrypter decrypter = null;

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
    private SAML2ResponseValidator responseValidator = null;

    /**
     * Assertion validator
     */
    private SAML2AssertionValidator assertionValidator = null;

    /**
     * Construct a SAML assertion consumer processor
     *
     * @param metaDataFilePath               metadata file path
     * @param idpId                          identity provider SAML entity identifier
     * @param customerCode                   identity provider internal Northgate customer code
     * @param idpProtocol                    identity provider SAML protocol to use
     * @param spId                           service provider id
     * @param mdHandler                      metadata handler
     * @param decryptionKeyStoreFilePath     The file path for the keystore holding the private key we as a service provider
     *                                       would use to decrypt incoming SAML messages.
     * @param decryptionKeyStoreFilePassword The password for the keystore holding the decryption key or null.
     * @param decryptionKeyAlias             The alias of the decryption key in the keystore or null;
     * @param decryptionKeyPassword          The password for the decryption key or null.
     */
    public SAML2AssertionConsumerProcessorImpl(final String metaDataFilePath,
                                               final String idpId,
                                               final String customerCode,
                                               final String idpProtocol,
                                               final String spId,
                                               final MetaDataHandler mdHandler,
                                               final String decryptionKeyStoreFilePath,
                                               final String decryptionKeyStoreFilePassword,
                                               final String decryptionKeyAlias,
                                               final String decryptionKeyPassword) {
        super(metaDataFilePath, idpId, customerCode, idpProtocol, spId, mdHandler);
        // Setup service provider decrypter given input keystore location and key access details, and whether we
        // as a service provider expect our content to be encrypted or not.
        this.decrypter = SAMLHelper.setupDecrypter(mdHandler.getEncryptionAlgorithm(serviceProvider),
                decryptionKeyStoreFilePath, decryptionKeyStoreFilePassword, decryptionKeyAlias, decryptionKeyPassword);
        this.responseValidator = SAML2ResponseValidatorFactory.getInstance(customerCode);
        this.assertionValidator = SAML2AssertionValidatorFactory.getInstance(customerCode);
    }

    /**
     * Construct a SAML assertion consumer processor
     *
     * @param mdProvider                     metadata provider
     * @param idpId                          identity provider SAML entity identifier
     * @param customerCode                   identity provider internal Northgate customer code
     * @param idpProtocol                    identity provider SAML protocol to use
     * @param spId                           service provider id
     * @param mdHandler                      metadata handler
     * @param decryptionKeyStoreFileStream   The file stream for the keystore holding the private key we as a service provider
     *                                       would use to decrypt incoming SAML messages.
     * @param decryptionKeyStoreFilePassword The password for the keystore holding the decryption key or null.
     * @param decryptionKeyAlias             The alias of the decryption key in the keystore or null;
     * @param decryptionKeyPassword          The password for the decryption key or null.
     */
    public SAML2AssertionConsumerProcessorImpl(final MetadataProvider mdProvider,
                                               final String idpId,
                                               final String customerCode,
                                               final String idpProtocol,
                                               final String spId,
                                               final MetaDataHandler mdHandler,
                                               final InputStream decryptionKeyStoreFileStream,
                                               final String decryptionKeyStoreFilePassword,
                                               final String decryptionKeyAlias,
                                               final String decryptionKeyPassword) {
        super(mdProvider, idpId, customerCode, idpProtocol, spId, mdHandler);
        // Setup service provider decrypter given input keystore location and key access details, and whether we
        // as a service provider expect our content to be encrypted or not.
        this.decrypter = SAMLHelper.setupDecrypter(mdHandler.getEncryptionAlgorithm(serviceProvider),
                decryptionKeyStoreFileStream, decryptionKeyStoreFilePassword, decryptionKeyAlias, decryptionKeyPassword);
        this.responseValidator = SAML2ResponseValidatorFactory.getInstance(customerCode);
        this.assertionValidator = SAML2AssertionValidatorFactory.getInstance(customerCode);
    }

    /**
     * Construct a SAML assertion consumer processor
     *
     * @param mdProvider   metadata provider
     * @param idpId        identity provider SAML entity identifier
     * @param customerCode identity provider internal Northgate customer code
     * @param idpProtocol  identity provider SAML protocol to use
     * @param spId         service provider id
     * @param mdHandler    metadata handler
     * @param decrypter    SAML2 assertion decrypter
     */
    public SAML2AssertionConsumerProcessorImpl(final MetadataProvider mdProvider,
                                               final String idpId,
                                               final String customerCode,
                                               final String idpProtocol,
                                               final String spId,
                                               final MetaDataHandler mdHandler,
                                               final Decrypter decrypter) {
        super(mdProvider, idpId, customerCode, idpProtocol, spId, mdHandler);
        this.decrypter = decrypter;
        this.responseValidator = SAML2ResponseValidatorFactory.getInstance(customerCode);
        this.assertionValidator = SAML2AssertionValidatorFactory.getInstance(customerCode);
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML2AssertionConsumerProcessor#getDecrypter()
     */
    public Decrypter getDecrypter() {
        return decrypter;
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML2AssertionConsumerProcessor#auditError(String, String)
     */
    public void auditError(String code, String details) {
        auditMessenger.auditError(code, idpId, idpProtocol, spId, details);
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML2AssertionConsumerProcessor#auditSuccess(String, String)
     */
    public void auditSuccess(String code, String details) {
        auditMessenger.auditSuccess(code, idpId, idpProtocol, spId, details);
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML2AssertionConsumerProcessor#validate(org.opensaml.saml2.core.Response)
     */
    public SAMLResponseValidationResult validate(Response response) {
        synchronized (LOCK) {
            return responseValidator.validate(response, SEEN_RESPONSE_IDS, MAX_MINUTES);
        }
    }

    /**
     * @see com.timepoorprogrammer.saml.impls.SAML2AssertionConsumerProcessor#validate(org.opensaml.saml2.core.Assertion, String)
     */
    public SAMLAssertionValidationResult validate(Assertion assertion, String issuer) {
        return assertionValidator.validate(assertion, issuer);
    }
}