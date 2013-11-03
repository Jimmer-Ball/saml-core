package com.timepoorprogrammer.saml.security.signature;

import com.timepoorprogrammer.saml.security.KeyStoreCredentialHandler;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;

/**
 * SAML signature creator class.
 *
 * @author Jim Ball
 */
public class X509SAMLSignatureCreator {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(X509SAMLSignatureCreator.class);
    /**
     * Key store credential handler
     */
    private KeyStoreCredentialHandler keyStoreCredentialHandler = null;
    /**
     * Global security configuration applied by OpenSAML
     */
    private SecurityConfiguration securityConfiguration;

    /**
     * Create a signature creator given the path to our local keystore and our keystore password.
     *
     * @param keyStorePath     path to keystore
     * @param keyStorePassword password for keystore
     */
    public X509SAMLSignatureCreator(final String keyStorePath, final String keyStorePassword) {
        if (keyStorePath == null || keyStorePassword == null) {
            throw new IllegalArgumentException("Cannot construct a signature creator without both keyStorePath and keyStorePassword");
        }
        keyStoreCredentialHandler = new KeyStoreCredentialHandler(keyStorePath, keyStorePassword);
        securityConfiguration = getSecurityConfiguration();
    }

    /**
     * Create a signature creator given the input stream to our keystore and our keystore password.
     *
     * @param keyStoreStream   input stream to keystore
     * @param keyStorePassword password for keystore
     */
    public X509SAMLSignatureCreator(final InputStream keyStoreStream, final String keyStorePassword) {
        if (keyStoreStream == null || keyStorePassword == null) {
            throw new IllegalArgumentException("Cannot construct a signature creator without both keyStoreStream and keyStorePassword");
        }
        keyStoreCredentialHandler = new KeyStoreCredentialHandler(keyStoreStream, keyStorePassword);
        securityConfiguration = getSecurityConfiguration();
    }

    /**
     * Finish the blank signature provided given the private key and the private key's password
     *
     * @param blankSignature blank signature
     * @param keyAlias       key alias
     * @param keyPassword    key password
     */
    public void finishSignature(Signature blankSignature, final String keyAlias, final String keyPassword) {
        if (keyAlias == null || keyPassword == null) {
            throw new IllegalArgumentException("Cannot finish signature without blankSignature to start with, keyAlias, and keyPassword");
        }
        try {
            // Setup the signing credentials to apply
            BasicX509Credential signingCredentials = keyStoreCredentialHandler.getSigningCredentials(keyAlias, keyPassword);
            blankSignature.setSigningCredential(signingCredentials);

            // What algorithm to apply to the signature depends on the algorithm used by the private
            // key, and what canonicalization algorithm to apply depends on what the XMLSig standard
            // expects.
            //
            // Inside OpenSAML, the canonicalization algorithm is hardcoded in global configuration, and the
            // routine for translating from a java key algorithm to the same thing expressed in XMLSig format
            // is also provided by the OpenSAML global security configuration class.
            //
            // From our perspective, if we are providing RSAwithSHA1 certificates for PKI we'd end up with
            // signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
            // signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            // but by delegating to OpenSAML's global security configuration means we aren't hard-coding the
            // signature algorithm details in our code, and let OpenSAML do the hard-work.
            blankSignature.setSignatureAlgorithm(securityConfiguration.getSignatureAlgorithmURI(signingCredentials.getPrivateKey().getAlgorithm()));
            blankSignature.setCanonicalizationAlgorithm(securityConfiguration.getSignatureCanonicalizationAlgorithm());

            // Add key information into the signature
            X509KeyInfoGeneratorFactory kiFactory = new X509KeyInfoGeneratorFactory();
            kiFactory.setEmitEntityCertificate(true);
            KeyInfo keyInfo = kiFactory.newInstance().generate(signingCredentials);
            blankSignature.setKeyInfo(keyInfo);
        } catch (Exception anyE) {
            final String errorMessage = "Error creating signature";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Get the OpenSAML global security configuration.
     *
     * @return OpenSAML global security configuration
     */
    public SecurityConfiguration getSecurityConfiguration() {
        SecurityConfiguration securityConfiguration = Configuration.getGlobalSecurityConfiguration();
        if (securityConfiguration != null) {
            return securityConfiguration;
        } else {
            final String errorMessage = "Error, unable to establish OpenSAML global security configuration";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }
}