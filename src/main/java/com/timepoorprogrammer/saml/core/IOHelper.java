package com.timepoorprogrammer.saml.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;

/**
 * Base methods for Input and Output Help
 *
 * @author Jim Ball
 */
public class IOHelper {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(IOHelper.class);

    /**
     * Build the path to a file under the JBOSS deployment configuration location under the JBOSS instance
     * conf sub-directory.
     * <p/>
     * Note: The system property used here is set during JBoss startup by the JBoss startup sequence.
     *
     * @param fileName file name
     * @return path to file under JBoss conf directory
     */
    public String buildJBossFilePath(final String fileName) {
        final Properties props = System.getProperties();
        final String homeDirectory = props.getProperty("jboss.server.home.dir", ".");
        log.debug("According to the environment our jboss.server.home.dir is set to: {}", homeDirectory);
        final String fileSeparator = props.getProperty("file.separator", "/");
        final String filePath = String.format(String.format("%1$s%2$sconf%2$s%3$s",
                homeDirectory, fileSeparator, fileName));
        log.debug("File path is " + filePath);
        return filePath;
    }

    /**
     * Build the path to a file under the TOMCAT deployment configuration location under a specific
     * TOMCAT instance conf sub-directory.
     * <p/>
     * Note: The system property used here is set during default TOMCAT startup.
     *
     * @param fileName file name
     * @return path to file under TOMCAT conf directory
     */
    public String buildTomcatFilePath(final String fileName) {
        final Properties props = System.getProperties();
        final String homeDirectory = props.getProperty("catalina.home", ".");
        log.debug("According to the environment our catalina.home is set to: {}", homeDirectory);
        final String fileSeparator = props.getProperty("file.separator", "/");
        final String filePath = String.format(String.format("%1$s%2$sconf%2$s%3$s",
                homeDirectory, fileSeparator, fileName));
        log.debug("File path is " + filePath);
        return filePath;
    }

    /**
     * Currently this method supports either TOMCAT or JBOSS, and as time goes on it could support more.
     * The method is to avoiding the need to amend hardcoded settings in web.xml files to point to the
     * right configuration directory for a given type of application server.
     *
     * @param fileName file name to look for
     * @return path to file
     */
    public String buildAppServerFilePath(final String fileName) {
        final Properties props = System.getProperties();
        String homeDirectory = props.getProperty("catalina.home", ".");
        log.debug("According to the environment our catalina.home is set to: " + homeDirectory);
        if (homeDirectory == null || homeDirectory.length() == 0) {
            homeDirectory = props.getProperty("jboss.server.home.dir", ".");
            log.debug("According to the environment our jboss.server.home.dir is set to: {}", homeDirectory);
            if (homeDirectory == null || homeDirectory.length() == 0) {
                final String errorMessage = "Settings required to determine configuration directory are missing";
                log.error(errorMessage);
                throw new RuntimeException(errorMessage);
            }
        }
        // Whatever the result of looking for the Tomcat or JBoss home directory
        // was, now build up the final path for return.
        final String fileSeparator = props.getProperty("file.separator", "/");
        final String filePath = String.format(String.format("%1$s%2$sconf%2$s%3$s",
                homeDirectory, fileSeparator, fileName));
        log.debug("File path is " + filePath);
        return filePath;
    }

    /**
     * Build the path to the test fixtures keystores held in the module
     * fixtures the module test is dependent on.
     *
     * @param keystoreFileName keystore file name
     * @return path to keystore under fixtures module
     */
    public String buildFixturesKeyStorePath(final String keystoreFileName) {
        final Properties props = System.getProperties();
        final String fileSeparator = props.getProperty("file.separator", "/");
        final String filePath = String.format("fixtures%1$skeystores%1$s%2$s", fileSeparator, keystoreFileName);
        log.debug("File path is " + filePath);
        return filePath;
    }

    /**
     * Build the path to the canned_saml files we'll use for validating the basic SAML functionality and features.
     *
     * @param subDirectory sub-directory under fixtures module -> canned_saml we look for a file
     * @param fileName     file name to look for
     * @return file handle.
     */
    public String buildFixturesXMLPath(final String subDirectory, final String fileName) {
        final Properties props = System.getProperties();
        final String fileSeparator = props.getProperty("file.separator", "/");
        final String filePath = String.format("fixtures%1$scanned_saml%1$s%2$s%1$s%3$s", fileSeparator, subDirectory, fileName);
        log.debug("File path is " + filePath);
        return filePath;
    }

    /**
     * Get hold of a file in a particular subdirectory of the fixtures location
     *
     * @param subDirectory sub directory name
     * @param fileName filename
     * @return Full path to file
     */
    public String buildFixturesSubdirectoryPath(final String subDirectory, final String fileName) {
        final Properties props = System.getProperties();
        final String fileSeparator = props.getProperty("file.separator", "/");
        final String filePath = String.format("fixtures%1$s%2$s%1$s%3$s", fileSeparator, subDirectory, fileName);
        log.debug("File path is " + filePath);
        return filePath;
    }

    /**
     * Open a file as an input stream.
     *
     * @param filePath file path
     * @return input stream
     */
    public InputStream openFileAsInputStream(final String filePath) {
        try {
            return new FileInputStream(filePath);
        } catch (Exception anyE) {
            final String errorMessage = "Error opening file as an input stream";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Close an input stream
     *
     * @param is input stream to close
     */
    public void closeInputStream(final InputStream is) {
        try {
            is.close();
        } catch (Exception anyE) {
            final String errorMessage = "Error closing input stream";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Open a file as an output stream.
     *
     * @param filePath file path
     * @return output stream
     */
    public OutputStream openFileAsOutputStream(final String filePath) {
        try {
            return new FileOutputStream(filePath);
        } catch (Exception anyE) {
            final String errorMessage = "Error opening file as an output stream";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Close an output stream
     *
     * @param os input stream to close
     */
    public void closeOutputStream(final OutputStream os) {
        try {
            os.close();
        } catch (Exception anyE) {
            final String errorMessage = "Error closing output stream";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }
}