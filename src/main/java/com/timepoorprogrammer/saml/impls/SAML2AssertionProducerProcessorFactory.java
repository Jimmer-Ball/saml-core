package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.common.FactoryBase;
import com.timepoorprogrammer.saml.impls.standard.producer.processor.SAML2AssertionProducerProcessorImpl;
import com.timepoorprogrammer.saml.common.FactoryBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.util.List;

/**
 * SAML2 Assertion producer processor factory.  As a SAML producer, we may need to apply a bespoke processor for SAML
 * content sent out to a particular remote service provider or partner.
 * <p/>
 * Any bespoke implementation class lives in the sub-package producer.processor of a partner or service specific
 * implementation under the impls package.
 * <p/>
 * The default producer implementation lives under com.northgatearinso.saml.impls.standard.producer.processor
 * and is called SAML2AssertionProducerProcessorImpl. If a bespoke processor isn't found then the factory
 * provides the default SAML2 implementation.
 * <p/>
 * A service provider or partner specific implementation would need to:
 * <p/>
 * <ul>
 * <li>Live under the service provider or partner specific package that matched the following path com.northgatearinso.saml.impls.<lowercase_serviceCode>.producer.processor</li>
 * <li>Implement the SAML2AssertionProducerProcessor interface</li>
 * <li>Hold the class name SAML2AssertionProducerProcessorImpl</li>
 * </ul>
 * <p/>
 * So for an example if we are sending an assertion to Salesforce or Google Apps then we need a partner or service
 * code for these guys, same as you would need a customer code for a customer, and the custom assertion producer
 * will need to live under the right directory, e.g. com.northgatearinso.saml.impls.sf.producer.processor might
 * be used to define the location for custom SAML producers for SAML11 and SAML2 being produced for Salesforce
 * cross-domain integration.
 * <p/>
 * Whether doing custom SAML producers or consumers, the metadata will likely hold the entity name provided by a
 * partner or service provider.  We will use this to lookup an internal Northgate partner code. The partner
 * code will be used to point to bespoke implementations that live in a partner specific directory.
 * <p/>
 * To configure it all properly, allow a partner to have whatever entity identifier they require in their metadata
 * and issuer field for outgoing SAML to them and update the samlentitytranslation.properties file with a mapping
 * between the internal Northgate partner code and the external SAML entity identifier used by the partner.
 *
 * @author Jim Ball
 */
public class SAML2AssertionProducerProcessorFactory extends FactoryBase {
    private static final Logger log = LoggerFactory.getLogger(SAML2AssertionProducerProcessorFactory.class);

    /**
     * Bespoke SAML2AssertionProducerProcessors have to live in the producer.processor subpackage of
     * a bespoke implementation.
     */
    private static final String BESPOKE_IMPL_SUB_PACKAGE_LOCATION = "producer.processor";

    /**
     * As a SAML producer, we may need to apply a custom processor for SAML content to be sent to a
     * remote service provider.
     *
     * @param metaDataFilePath            metadata file path
     * @param idpId                       The identity provider SAML entity identifier as used in SAML metadata and
     *                                    SAML entities used by us (for example https://idp.webview.nghr.com)
     * @param idpProtocol                 The SAML protocol (either 2.0 or 1.1) our identity provider uses to create
     *                                    SAML messages, so SAMLConstants.SAML20P_NS == urn:oasis:names:tc:SAML:2.0:protocol
     * @param serviceCode                 The internal Northgate code for the partner or service provider we are
     *                                    sending SAML to.
     * @param spId                        The service provider SAML entity identifier as used in SAML metadata and
     *                                    SAML payload bound for the partner (for example https://saml.salesforce.com)
     * @param mdHandler                   metadata handler
     * @param signingKeyStoreFilePath     The file path for the keystore holding the private key we as a identity
     *                                    provider would use to sign an outbound SAML message or null.
     * @param signingKeyStoreFilePassword The password for the keystore holding the signing key or null.
     * @param signingKeyAlias             The alias of the signing key in the keystore or null;
     * @param signingKeyPassword          The password for the signing key or null.
     * @return the correct implementation of a SAML2AssertionProducerProcessor
     */
    @SuppressWarnings("unchecked")
    public static SAML2AssertionProducerProcessor getInstance(final String metaDataFilePath,
                                                              final String idpId,
                                                              final String idpProtocol,
                                                              final String serviceCode,
                                                              final String spId,
                                                              final MetaDataHandler mdHandler,
                                                              final String signingKeyStoreFilePath,
                                                              final String signingKeyStoreFilePassword,
                                                              final String signingKeyAlias,
                                                              final String signingKeyPassword) {
        if (spId != null && serviceCode != null) {
            final List<String> details = parseClassName(SAML2AssertionProducerProcessor.class.getName());
            String fullPath = null;
            try {
                // If a partner needs a bespoke assertion producer, then we would need to create a
                // partner specific directory holding a sub package producer.processor with a
                // bespoke implementation within it.
                fullPath = buildPathToBespokeImplementation(serviceCode, details.get(0), details.get(1), BESPOKE_IMPL_SUB_PACKAGE_LOCATION);
                final Class implementation = Class.forName(fullPath);
                final Class[] argSignature = new Class[]{String.class, String.class, String.class, String.class,
                        String.class, MetaDataHandler.class, String.class, String.class, String.class,
                        String.class};
                final Constructor constructor = implementation.getConstructor(argSignature);
                return (SAML2AssertionProducerProcessor) constructor.newInstance(metaDataFilePath, idpId, idpProtocol,
                        serviceCode, spId, mdHandler, signingKeyStoreFilePath,
                        signingKeyStoreFilePassword, signingKeyAlias,
                        signingKeyPassword);
            }
            catch (ClassNotFoundException recoverableE) {
                final String debugMessage = "Class not found " + fullPath + ", issue is " +
                        recoverableE.getClass().getName() + ", so returning the default implementation.";
                log.debug(debugMessage);
                // Return the default implementation
                return new SAML2AssertionProducerProcessorImpl(metaDataFilePath, idpId, idpProtocol, serviceCode, spId,
                        mdHandler, signingKeyStoreFilePath, signingKeyStoreFilePassword, signingKeyAlias, signingKeyPassword);
            }
            catch (Throwable anyE) {
                final String errorMessage = "Error obtaining implementation";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            final String errorMessage = "Cannot look for a bespoke producer processor implementation as we've no target service provider or partner code";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }
}