package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.common.FactoryBase;
import com.timepoorprogrammer.saml.impls.standard.common.AuditMessengerImpl;
import com.timepoorprogrammer.saml.impls.standard.common.AuditMessengerImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.util.List;


/**
 * Audit Messenger factory
 *
 * @author Jim Ball
 */
public class AuditMessengerFactory extends FactoryBase {
    private static final Logger log = LoggerFactory.getLogger(AuditMessengerFactory.class);

    /**
     * Bespoke AuditMessengers have to live in the common subpackage of a bespoke implementation.
     */
    private static final String BESPOKE_IMPL_SUB_PACKAGE_LOCATION = "common";

    /**
     * Return an instance of an audit messenger. Any bespoke audit messenger implementation
     * classes live in the common sub-package of a customer or destination service partner
     * specific implementation under the impls package.
     * <p/>
     * The default audit messenger implementation lives under com.northgatearinso.saml.impls.standard.common
     * and is called AuditMessengerImpl. If a bespoke audit messenger isn't found then the factory provides
     * the default implementation.
     * <p/>
     * A customer specific implementation would need to:
     * <p/>
     * <ul>
     * <li>Live under the customer specific package that matched the following path com.northgatearinso.saml.impls.<lowercase_bespokeCode>.common</li>
     * <li>Implement the AuditMessenger interface</li>
     * <li>Hold the class name AuditMessengerImpl</li>
     * </ul>
     * <p/>
     * If you stick to the package and class naming rules above you can easily provide your own bespoke implementations.
     *
     * @param bespokeCode bespoke code
     * @return bespoke or default implementation
     */
    @SuppressWarnings("unchecked")
    public static AuditMessenger getInstance(final String bespokeCode) {
        if (bespokeCode == null) {
            log.debug("Returning default audit messenger implementation");
            return new AuditMessengerImpl();
        } else {
            log.debug("Looking for bespoke audit messenger implementation");
            final List<String> details = parseClassName(AuditMessenger.class.getName());
            String fullPath = null;
            try {               
                fullPath = buildPathToBespokeImplementation(bespokeCode, details.get(0), details.get(1), BESPOKE_IMPL_SUB_PACKAGE_LOCATION);
                final Class implementation = Class.forName(fullPath);
                final Class[] argSignature = new Class[]{};
                final Constructor constructor = implementation.getConstructor(argSignature);
                return (AuditMessenger) constructor.newInstance();
            }
            catch (ClassNotFoundException recoverableE) {
                final String debugMessage = "Class not found at " + fullPath + ", issue is " +
                        recoverableE.getClass().getName() + ", so returning the default implementation.";
                log.debug(debugMessage);
                return new AuditMessengerImpl();
            }
            catch (Throwable anyE) {
                final String errorMessage = "Error obtaining implementation";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        }
    }
}