package com.timepoorprogrammer.saml.impls;

import org.opensaml.saml2.metadata.SSODescriptor;

/**
 * Audit Messenger interface for any implementation responsible for creating audit trail messages within the
 * SAML framework.
 *
 * @author Jim Ball
 */
public interface AuditMessenger {

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
                           final String message);

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
                             final String message);

    /**
     * Get the entity descriptor for whoom an audit message may be bound.
     *
     * @return SSO descriptor for target descriptor
     */
    public SSODescriptor getEntityDescriptor();

    /**
     * Set the entity descriptor for whoom an audit message may be bound. Passing
     * in the entity descriptor allows an implementation to rummage around in the
     * SAML metadata definition of an entity.  Why it would want to do this is up to the
     * implementation, but an example would be sending email out to the contact details
     * for a given organisation via the email contact details embedded in the entity
     * descriptor.
     *
     * @param entityDescriptor entity descriptor
     */
    public void setEntityDescriptor(final SSODescriptor entityDescriptor);
}