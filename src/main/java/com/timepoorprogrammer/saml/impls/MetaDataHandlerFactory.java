package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.common.FactoryBase;
import com.timepoorprogrammer.saml.impls.standard.metadata.MetaDataHandlerImpl;
import com.timepoorprogrammer.saml.common.FactoryBase;
import com.timepoorprogrammer.saml.impls.standard.metadata.MetaDataHandlerImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.util.List;

/**
 * Metadata handler factory
 *
 * @author Jim Ball
 */
public class MetaDataHandlerFactory extends FactoryBase {
    private static final Logger log = LoggerFactory.getLogger(MetaDataHandlerFactory.class);

    /**
     * Bespoke MetaDataHandlers have to live in the metadata subpackage of a bespoke implementation.
     */
    private static final String BESPOKE_IMPL_SUB_PACKAGE_LOCATION = "metadata";

    /**
     * Return an instance of a metadata handler. Any bespoke metadata handler implementation
     * classes live in the metadata sub-package of a customer specific implementation under
     * the impls package.
     * <p/>
     * The default metadata handler implementation lives under com.northgatearinso.saml.impls.standard.metadata
     * and is called MetaDataHandlerImpl. If a bespoke metadata handler isn't found then the factory provides
     * the default implementation.
     * <p/>
     * A customer specific implementation would need to:
     * <p/>
     * <ul>
     * <li>Live under the customer specific package that matched the following path com.northgatearinso.saml.impls.<lowercase_customer_code>.metadata</li>
     * <li>Implement the MetaDataHandler interface</li>
     * <li>Hold the class name MetaDataHandlerImpl</li>
     * </ul>
     * <p/>
     * If you stick to the package and class naming rules above you can provide your own bespoke implementation in the
     * right place. But to implement a custom metadata handler, you really need to understand the SAML metadata
     * specification, and you need to match it up with the expected metadata that you might
     * get with a third-party to change the processing rules correctly. Go see document
     * saml-metadata-2.0-os.pdf you can pick up from the OASIS site for the specification (or
     * project docs directory) and check my comments in the default MetaDataHandlerImpl to see
     * my payload structure assumptions that are applied to any incoming SAML content.
     * <p/>
     * Please note this the hardest class to bespoke out of all the processors/handlers in the library.
     *
     * @param bespokeCode bespoke code
     * @return bespoke or default implementation
     */
    @SuppressWarnings("unchecked")
    public static MetaDataHandler getInstance(final String bespokeCode) {
        if (bespokeCode == null) {
            log.debug("Returning default metadata handling implementation");
            return new MetaDataHandlerImpl();
        } else {
            log.debug("Looking for bespoke metadata handling implementation");
            final List<String> details = parseClassName(MetaDataHandler.class.getName());
            String fullPath = null;
            try {
                fullPath = buildPathToBespokeImplementation(bespokeCode, details.get(0), details.get(1), BESPOKE_IMPL_SUB_PACKAGE_LOCATION);
                final Class implementation = Class.forName(fullPath);
                final Class[] argSignature = new Class[]{};
                final Constructor constructor = implementation.getConstructor(argSignature);
                return (MetaDataHandler) constructor.newInstance();
            }
            catch (ClassNotFoundException recoverableE) {
                final String debugMessage = "Class not found at " + fullPath + ", issue is " +
                        recoverableE.getClass().getName() + ", so returning the default implementation.";
                log.debug(debugMessage);
                return new MetaDataHandlerImpl();
            }
            catch (Throwable anyE) {
                final String errorMessage = "Error obtaining implementation";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        }
    }
}


