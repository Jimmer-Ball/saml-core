package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.common.FactoryBase;
import com.timepoorprogrammer.saml.impls.standard.consumer.processor.SAML11AssertionConsumerProcessorImpl;
import com.timepoorprogrammer.saml.common.FactoryBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.util.List;

/**
 * SAML1.1 Assertion consumer processor factory.  As a SAML consumer, we may need to apply a bespoke processor for SAML
 * content sent from a remote identity provider.
 * <p/>
 * The internal Northgate customer code of an identity provider is used to identify a bespoke code implementation
 * <p/>
 * Any bespoke implementation class lives in the sub-package consumer.processor of a customer specific
 * implementation under the impls package.
 * <p/>
 * The default consumer implementation lives under com.northgatearinso.saml.impls.standard.consumer.processor
 * and is called SAML11AssertionConsumerProcessorImpl. If a bespoke processor isn't found then the factory
 * provides the default SAML11 implementation.
 * <p/>
 * A customer specific implementation would need to:
 * <p/>
 * <ul>
 * <li>Live under the customer specific package that matched the following path com.northgatearinso.saml.impls.<lowercase_customerCode>.consumer.processor</li>
 * <li>Implement the SAML11AssertionConsumerProcessor interface</li>
 * <li>Hold the class name SAML11AssertionConsumerProcessorImpl</li>
 * </ul>
 * <p/>
 * If you stick to the package and class naming rules above you can easily provide your own bespoke implementations.
 * <p/>
 * Whether doing custom SAML producers or consumers, the metadata will hold the entity name provided by a
 * customer.  We will use this to lookup an internal Northgate customer code. The customer code will be used
 * to point to bespoke implementations that live in a customer specific directory. The directory needs to be
 * the lowercase version of the customer code, and routing information needs to exist in the saml.properties
 * given the customer code.
 * <p/>
 * As a rule the customer code is the same as the prefix used in MyView and ResourceLink and hosting to
 * identify customers.  This is usually a 2 character code.
 * <p/>
 * To configure it all properly, allow a customer to have whatever entity identifier they require in their metadata
 * and issuer field on the incoming SAML and update the samlentitytranslation.properties file with a mapping between
 * the internal Northgate customer code and the external SAML entity identifier used by the customer.
 *
 * @author Jim Ball
 */
public class SAML11AssertionConsumerProcessorFactory extends FactoryBase {
    private static final Logger log = LoggerFactory.getLogger(SAML11AssertionConsumerProcessorFactory.class);
    /**
     * Bespoke SAML11AssertionConsumerProcessors have to live in the consumer.processor subpackage of
     * a bespoke implementation.
     */
    private static final String BESPOKE_IMPL_SUB_PACKAGE_LOCATION = "consumer.processor";

    /**
     * As a SAML consumer, we may need to apply a bespoke processor for SAML content sent by a remote
     * identity provider.
     *
     * @param metaDataFilePath metadata file path
     * @param idpId            Identity provider SAML entity identifier (or URL) as pulled from the SAML metadata
     * @param customerCode     Customer code of identity provider within Northgate
     * @param idpProtocol      The SAML protocol (either 2.0 or 1.1) our identity provider uses to create SAML messages, so either
     *                         SAMLConstant.SAML11P_NS == urn:oasis:names:tc:SAML:1.1:protocol, or SAMLConstants.SAML20P_NS ==
     *                         urn:oasis:names:tc:SAML:2.0:protocol
     * @param spId             service provider id
     * @param mdHandler        metadata handler
     * @return SAML11AssertionConsumerProcessor
     */
    @SuppressWarnings("unchecked")
    public static SAML11AssertionConsumerProcessor getInstance(final String metaDataFilePath,
                                                               final String idpId,
                                                               final String customerCode,
                                                               final String idpProtocol,
                                                               final String spId,
                                                               final MetaDataHandler mdHandler) {
        if (idpId != null && customerCode != null) {
            final List<String> details = parseClassName(SAML11AssertionConsumerProcessor.class.getName());
            String fullPath = null;
            try {
                // If a customer needs a bespoke assertion consumer, then we would need to create a
                // customer specific directory holding a sub package consumer.processor with a
                // bespoke implementation within it that matches a Northgate customer code.
                fullPath = buildPathToBespokeImplementation(customerCode, details.get(0), details.get(1), BESPOKE_IMPL_SUB_PACKAGE_LOCATION);
                final Class implementation = Class.forName(fullPath);
                final Class[] argSignature = new Class[]{String.class, String.class, String.class, String.class, String.class, MetaDataHandler.class};
                final Constructor constructor = implementation.getConstructor(argSignature);
                return (SAML11AssertionConsumerProcessor) constructor.newInstance(metaDataFilePath, idpId, customerCode, idpProtocol, spId, mdHandler);
            }
            catch (ClassNotFoundException recoverableE) {
                final String debugMessage = "Class not found at " + fullPath + ", issue is " +
                        recoverableE.getClass().getName() + ", so returning the default implementation.";
                log.debug(debugMessage);
                return new SAML11AssertionConsumerProcessorImpl(metaDataFilePath, idpId, customerCode, idpProtocol, spId, mdHandler);
            }
            catch (Throwable anyE) {
                final String errorMessage = "Error obtaining implementation";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "Cannot look for a bespoke consumer processor implementation as we've no target identity provider";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }
}