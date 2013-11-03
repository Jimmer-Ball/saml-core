package com.timepoorprogrammer.saml.security;

import com.timepoorprogrammer.saml.TestHelper;
import com.timepoorprogrammer.saml.core.IOHelper;
import com.timepoorprogrammer.saml.security.KeyStoreReader;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;

public class KeyStoreReaderTest {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(KeyStoreReaderTest.class);

    /**
     * Open up a keystore and read out the contents of the keystore
     */
    @Test
    public void testMainScenario() {
        final IOHelper ioHelper = new IOHelper();
        // Open the named keystore found in the fixtures module
        final String keyStorePath = TestHelper.getFullPath("^.*fixtures\\\\keystores\\\\clientKeyStore.jks$");
        final InputStream keyStream = ioHelper.openFileAsInputStream(keyStorePath);
        if (keyStream != null) {
            // I just happen to know that the cert_cr.cmd applied in <JBOSS_SERVER>/conf uses the following password
            // when generating the keys used by Northgate applications
            String storePassword = "rmi+ssl";
            String keyPassword = "rmi+ssl";
            try {
                KeyStore keystore = KeyStoreReader.loadKeyStore(keyStream, storePassword);
                // For each alias in the store
                for (String alias : KeyStoreReader.getAliases(keystore)) {
                    log.info("Alias: " + alias);
                    if (alias.equals("remoteservice")) {
                        Key key = KeyStoreReader.getKey(keystore, alias, "remoteservice");
                        if (key != null) {
                            log.info("SERVICE KEY:\n" + KeyStoreReader.showDetails(key));
                        }
                        Certificate certificate = KeyStoreReader.getCertificate(keystore, alias);
                        if (certificate != null) {
                            log.info("SERVICE CERTIFICATE:\n" + KeyStoreReader.showDetails(certificate));
                        }
                    } else if (alias.equals("localclient")) {
                        Key key = KeyStoreReader.getKey(keystore, alias, "localclient");
                        if (key != null) {
                            log.info("CLIENT KEY:\n" + KeyStoreReader.showDetails(key));
                        }
                        Certificate certificate = KeyStoreReader.getCertificate(keystore, alias);
                        if (certificate != null) {
                            log.info("CLIENT CERTIFICATE:\n" + KeyStoreReader.showDetails(certificate));
                        }
                    } else if (alias.equals("tw")) {
                        Key key = KeyStoreReader.getKey(keystore, alias, "timewarner");
                        if (key != null) {
                            log.info("TW KEY:\n" + KeyStoreReader.showDetails(key));
                        }
                        Certificate certificate = KeyStoreReader.getCertificate(keystore, alias);
                        if (certificate != null) {
                            log.info("TW CERTIFICATE:\n" + KeyStoreReader.showDetails(certificate));
                        }
                    }
                    else {
                        Key key = KeyStoreReader.getKey(keystore, alias, keyPassword);
                        if (key != null) {
                            log.info("SOME OTHER KEY:\n" + KeyStoreReader.showDetails(key));
                        }
                        Certificate certificate = KeyStoreReader.getCertificate(keystore, alias);
                        if (certificate != null) {
                            log.info("SOME OTHER CERTIFICATE:\n" + KeyStoreReader.showDetails(certificate));
                        }
                    }
                }
            } catch (Exception anyE) {
                Assert.fail("Error processing keystore: " + anyE.getMessage());
            }
            finally {
                ioHelper.closeInputStream(keyStream);
            }
        } else {
            Assert.fail("Cannot find keystore to process");
        }
    }
}
