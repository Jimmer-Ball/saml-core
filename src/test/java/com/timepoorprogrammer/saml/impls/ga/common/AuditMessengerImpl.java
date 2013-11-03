package com.timepoorprogrammer.saml.impls.ga.common;

import com.timepoorprogrammer.saml.impls.AuditMessenger;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Custom audit messenger implementation.  This is responsible for writing out
 * SAML production and consumption audit messages to the application server log.
 * <p/>
 * The first iteration just uses logging, but others could use email gleaned from the
 * SAML metadata entity descriptor if required to send email on SAML processing errors
 * (for example) to the entity provided at construction.
 *
 * For details on how to provide a customer specific bespoke version of this, go and look
 * at the javadoc against the factory AuditMessengerFactory.
 *
 * @author Jim Ball
 */
public class AuditMessengerImpl implements AuditMessenger {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(AuditMessengerImpl.class);
    private SSODescriptor entityDescriptor;

    /**
     * Default constructor
     */
    public AuditMessengerImpl() {
    }

    /**
     * Raise an error message with auditing
     *
     * @param messagePrefix message prefix (e.g. "SAML PRODUCER AUDIT ERROR MESSAGE")
     * @param idpId         identity provider id
     * @param idpProtocol   identity provider protocol (e.g. SAML2)
     * @param spId          service provider identity
     * @param message       message to put in audit trail
     */
    public void auditError(final String messagePrefix,
                           final String idpId,
                           final String idpProtocol,
                           final String spId,
                           final String message) {
        log.info(String.format("%s: IdP: %s, PROTOCOL: %s, SP: %s, MESSAGE: %s",
                messagePrefix, idpId, idpProtocol, spId, message));
    }

    /**
     * Raise a success message with auditing
     *
     * @param messagePrefix message prefix (e.g. "SAML PRODUCER AUDIT SUCCESS MESSAGE")
     * @param idpId         identity provider id
     * @param idpProtocol   identity provider protocol (e.g. SAML2)
     * @param spId          service provider identity
     * @param message       message to put in audit trail
     */
    public void auditSuccess(final String messagePrefix,
                             final String idpId,
                             final String idpProtocol,
                             final String spId,
                             final String message) {
        log.info(String.format("%s: IdP: %s, PROTOCOL: %s, SP: %s, MESSAGE: %s",
                messagePrefix, idpId, idpProtocol, spId, message));
    }

    /**
     * Get the entity descriptor for whoom an audit message could be tied up with.
     *
     * @return SSO descriptor for target descriptor
     */
    public SSODescriptor getEntityDescriptor() {
        return entityDescriptor;
    }

    /**
     * Set the entity descriptor for whoom an audit message may be bound. Passing
     * in the entity descriptor allows an implementation to rummage around in the
     * SAML metadata definition of an entity.  Why it would want to do this is up to the
     * implementation, but an example would be sending email out to the contact details
     * for a given organisation via the email contact details embedded in the entity
     * descriptor.
     *
     * This particular implementation doesn't do anything with the entityDescriptor
     * it just delegates to the logging subsystem, but a bespoke version could happily
     * make use of the entity details in a bespoke manner.
     *
     * @param entityDescriptor entity descriptor
     */
    public void setEntityDescriptor(final SSODescriptor entityDescriptor) {
        if (entityDescriptor != null) {
        this.entityDescriptor = entityDescriptor;
        } else {
            final String errorMessage = "Cannot set a null entity descriptor";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }
}