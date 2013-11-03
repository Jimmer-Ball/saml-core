package com.timepoorprogrammer.saml.impls;

import com.timepoorprogrammer.saml.common.FactoryBase;
import com.timepoorprogrammer.saml.impls.standard.consumer.processor.SAML2ResponseValidatorImpl;
import com.timepoorprogrammer.saml.common.FactoryBase;
import com.timepoorprogrammer.saml.impls.standard.consumer.processor.SAML2ResponseValidatorImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * SAML2 Response validator factory.  As a SAML consumer, we may need to apply a bespoke validator for SAML2
 * response content sent from a remote identity provider.
 * <p/>
 * Any bespoke implementation class lives in the sub-package consumer.processor of a customer specific
 * implementation under the impls package.
 * <p/>
 * The default consumer implementation lives under com.northgatearinso.saml.impls.standard.consumer.processor
 * and is called SAML2ResponseValidatorImpl. If a bespoke processor isn't found then the factory
 * provides the default SAML2 implementation.
 * <p/>
 * A customer specific implementation would need to:
 * <p/>
 * <ul>
 * <li>Live under the customer specific package that matched the following path
 * com.northgatearinso.saml.impls.<lowercase_customerCode>.consumer.processor</li>
 * <li>Implement the SAML2ResponseValidator interface</li>
 * <li>Hold the class name SAML2ResponseValidatorImpl</li>
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
public class SAML2ResponseValidatorFactory extends FactoryBase {
    private static final Logger log = LoggerFactory.getLogger(SAML2ResponseValidatorFactory.class);

    /**
     * Bespoke SAML2ResponseValidators have to live in the consumer.processor subpackage of a
     * bespoke implementation.
     */
    private static final String BESPOKE_IMPL_SUB_PACKAGE_LOCATION = "consumer.processor";

    /**
     * As a SAML consumer, we may need to apply a custom response validator for SAML 2 content sent by a remote
     * identity provider.
     *
     * @param customerCode Customer code of identity provider within Northgate
     * @return instance of a SAML2ResponseValidator
     */
    @SuppressWarnings("unchecked")
    public static SAML2ResponseValidator getInstance(final String customerCode) {
        if (customerCode != null) {
            final List<String> details = parseClassName(SAML2ResponseValidator.class.getName());
            String fullPath = null;
            try {
                // If a customer needs a bespoke response validator, then we would need to create a
                // customer specific directory holding a sub package consumer.processor with a
                // bespoke implementation within it.
                fullPath = buildPathToBespokeImplementation(customerCode, details.get(0), details.get(1), BESPOKE_IMPL_SUB_PACKAGE_LOCATION);
                final Class implementation = Class.forName(fullPath);
                return (SAML2ResponseValidator) implementation.newInstance();
            } catch (ClassNotFoundException recoverableE) {
                final String debugMessage = "Class not found at " + fullPath + ", issue is " +
                        recoverableE.getClass().getName() + ", so returning the default implementation.";
                log.debug(debugMessage);
                // Return the default implementation
                return new SAML2ResponseValidatorImpl();
            } catch (Throwable anyE) {
                final String errorMessage = "Error obtaining implementation";
                log.error(errorMessage, anyE);
                throw new RuntimeException(errorMessage, anyE);
            }
        } else {
            // Return the default validator
            return new SAML2ResponseValidatorImpl();
        }
    }
}

