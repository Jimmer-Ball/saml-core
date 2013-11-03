package com.timepoorprogrammer.saml.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Abstract factory base holding helper methods all the factories use and all bespoke code can use.
 * <p/>
 * The pattern for any bespoke code implementation needs to be packagePathToInterface +
 * bespokeCode.toLowerCase() + "." + subPackageName + "." + interfaceName + Impl;
 * <p/>
 * So, if we wanted to provided a bespoke SAML1.1 consumer processor for British Airways (bespokeCode of BA)
 * we would create a class in package
 * <p/>
 * com.ngahr.saml.impls (so where SAML11AssertionConsumerProcessor lives) + ba + consumer.processor (so where the
 * SAML11AssertionConsumerProcessorFactory expects them to live)
 * <p/>
 * of name SAML11AssertionConsumerProcessorImpl.java.
 * <p/>
 * Then if we called the factory with the bespoke code "BA" it would pick the specialised implementation class correctly.
 *
 * @author Jim Ball
 */
public abstract class FactoryBase {
    private static final Logger log = LoggerFactory.getLogger(FactoryBase.class);

    /**
     * Any bespoke implementation needs follow a naming convention, which is, the name of the implementation equals
     * the name of the interface the implementation meets plus the following postfix.
     */
    private static final String IMPLEMENTATION_POSTFIX = "Impl";

    /**
     * Parse the input className details given, in order to extract the
     * package location and the class name for this class. Used for relative
     * lookup of bespoke classes in subdirectories.
     *
     * @param className class name holding full path to the class
     * @return string array holding the package path and class name as elements 0 and 1 respectively
     */
    public static List<String> parseClassName(String className) {
        if (className == null) {
            throw new IllegalArgumentException("Missing class name so cannot parse it");
        }
        List<String> returnStrs = new ArrayList<String>(0);
        int index = className.lastIndexOf('.');
        if (index == -1) {
            String message = "Please provide the full Class.getName() details as this includes the package";
            log.error(message);
            throw new RuntimeException(message);
        } else {
            String packageName = className.substring(0, index + 1);
            className = className.substring(index + 1);
            returnStrs.add(packageName);
            returnStrs.add(className);
        }
        return returnStrs;
    }

    /**
     * Build the full path to the bespoke implementation of a class that is bespoke-able.
     * <p/>
     * This method here is to ensure all the factories adhere to the same convention when looking for a
     * bespoke implementation of a bespoke-able class. The convention is to put the bespoke code in
     * customer/service/partner specific sub-packages under the main implementations.  See the factory
     * classes for more details.
     *
     * @param bespokeCode    bespoke code used to find the root directory holding customer specific code
     * @param packagePath    The package path to the interface the implementation uses.  So, this assumes the project is
     *                       organised a certain way in terms of package layout.
     * @param interfaceName  The name of the interface the implementation meets.
     * @param subPackageName The sub-package within the customer specific code the implementation lives under.
     * @return The expected full path to the customer specific implementation.
     */
    public static String buildPathToBespokeImplementation(final String bespokeCode, final String packagePath, final String interfaceName, final String subPackageName) {
        if (bespokeCode == null || packagePath == null || interfaceName == null || subPackageName == null) {
            throw new IllegalArgumentException("Insufficient information provided to build a path to a bespoke implementation class");
        }
        return packagePath + bespokeCode.toLowerCase() + "." + subPackageName + "." + interfaceName + IMPLEMENTATION_POSTFIX;
    }
}
