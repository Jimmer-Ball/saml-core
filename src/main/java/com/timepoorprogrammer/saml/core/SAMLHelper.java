package com.timepoorprogrammer.saml.core;

import com.timepoorprogrammer.common.utilities.io.ArtifactHelper;
import com.timepoorprogrammer.common.utilities.io.Common;
import com.timepoorprogrammer.common.utilities.io.artifacts.Artifact;
import com.timepoorprogrammer.saml.security.KeyStoreCredentialHandler;
import com.timepoorprogrammer.saml.security.signature.X509SAMLSignatureCreator;
import com.timepoorprogrammer.saml.security.signature.X509SAMLSignatureCreator;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.xml.encryption.ChainingEncryptedKeyResolver;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;

import java.io.InputStream;
import java.net.URL;
import java.util.List;

/**
 * Helper utilities for the SAML library
 *
 * @author Jim Ball
 */
public class SAMLHelper {

    /**
     * Is this actually a URL resource
     *
     * @param name name
     * @return true if a URL, false otherwise
     */
    public static boolean isActuallyAResource(final String name) {
        boolean isURL = true;
        try {
            new URL(name);
        } catch (Exception anyE) {
            isURL = false;
        }
        return isURL;
    }

    /**
     * Convert the input name into a URL
     *
     * @param name input name
     * @return URL or null;
     */
    public static URL convertToURL(final String name) {
        try {
            return new URL(name);
        } catch (Exception anyE) {
            return null;
        }
    }

    /**
     * Given the input pattern go pickup any artifacts found under the test-classes output directory that match
     * whether we are running under maven or not.
     *
     * @param pattern pattern to look for on the class path
     * @return artifacts(s)
     */
    public static List<Artifact> getArtifacts(final String pattern) {
        ArtifactHelper artifactHelper = new ArtifactHelper();
        List<Artifact> artifacts;
        if (!Common.runningUnderMaven()) {
            artifacts = artifactHelper.getArtifactRecords(pattern, null);
        } else {
            artifacts = artifactHelper.getArtifactRecords(pattern, null, artifactHelper.getMavenRunnerManifest().getClassPathResources());
        }
        return artifacts;
    }

    /**
     * Given the input pattern go pickup any artifacts found under the test-classes output directory that match
     * whether we are running under maven or not.
     *
     * @param pattern         pattern to look for on the class path
     * @param resourcePattern Limiting pattern applied to overall classpath available to limit the scope of the search
     * @return artifacts(s)
     */
    public static List<Artifact> getArtifacts(final String pattern, final String resourcePattern) {
        ArtifactHelper artifactHelper = new ArtifactHelper();
        List<Artifact> artifacts;
        if (!Common.runningUnderMaven()) {
            artifacts = artifactHelper.getArtifactRecords(pattern, resourcePattern);
        } else {
            artifacts = artifactHelper.getArtifactRecords(pattern, resourcePattern, artifactHelper.getMavenRunnerManifest().getClassPathResources());
        }
        return artifacts;
    }

    /**
     * Get the full path to what is expected to be a unique file
     *
     * @param pattern pattern to look for on the class path
     * @return file path
     */
    public static String getFullPath(final String pattern) {
        List<Artifact> artifacts = SAMLHelper.getArtifacts(pattern);
        if (artifacts.size() != 1) {
            throw new RuntimeException("Either the file matching pattern " + pattern + " is missing, or more than one file matches");
        }
        return artifacts.get(0).getPath();
    }

    /**
     * Get the full path to what is expected to be a unique file
     *
     * @param pattern         pattern to look for on the class path
     * @param resourcePattern Limiting pattern applied to overall classpath available to limit the scope of the search
     * @return file path
     */
    public static String getFullPath(final String pattern, final String resourcePattern) {
        List<Artifact> artifacts = SAMLHelper.getArtifacts(pattern, resourcePattern);
        if (artifacts.size() != 1) {
            throw new RuntimeException("Either the file matching pattern " + pattern + " is missing, or more than one file matches");
        }
        return artifacts.get(0).getPath();
    }

    /**
     * Create XML digital signer
     *
     * @param privateKeyStorePath     private key store path
     * @param privateKeyStorePassword password for the private key store
     * @return XML digital signer or null
     */
    public static X509SAMLSignatureCreator createSignatureCreator(final String privateKeyStorePath,
                                                                  final String privateKeyStorePassword) {
        if (privateKeyStorePath != null && privateKeyStorePassword != null) {
            try {
                return new X509SAMLSignatureCreator(privateKeyStorePath, privateKeyStorePassword);
            } catch (Exception anyE) {
                throw new RuntimeException("Error setting up XML signature creator");
            }
        } else {
            return null;
        }
    }

    /**
     * Create XML digital signer
     *
     * @param privateKeyStoreURL      private key store URL
     * @param privateKeyStorePassword password for the private key store
     * @return XML digital signer
     */
    public static X509SAMLSignatureCreator createSignatureCreator(final URL privateKeyStoreURL,
                                                                  final String privateKeyStorePassword) {
        if (privateKeyStoreURL != null && privateKeyStorePassword != null) {
            try {
                return new X509SAMLSignatureCreator(privateKeyStoreURL.openStream(), privateKeyStorePassword);
            } catch (Exception anyE) {
                throw new RuntimeException("Error setting up XML signature creator");
            }
        } else {
            return null;
        }
    }

    /**
     * Create XML digital signer
     *
     * @param privateKeyStoreStream   private key store stream
     * @param privateKeyStorePassword password for the private key store
     * @return XML digital signer
     */
    public static X509SAMLSignatureCreator createSignatureCreator(InputStream privateKeyStoreStream,
                                                                  final String privateKeyStorePassword) {
        if (privateKeyStoreStream != null && privateKeyStorePassword != null) {
            try {
                return new X509SAMLSignatureCreator(privateKeyStoreStream, privateKeyStorePassword);
            } catch (Exception anyE) {
                throw new RuntimeException("Error setting up XML signature creator");
            }
        } else {
            return null;
        }
    }

    /**
     * Setup the SAML2 decrypter if we were given the full set of private key details
     *
     * @param encryptionAlgorithm            encryption algorithm name or null
     * @param decryptionKeyStoreFileStream   file stream for keystore holding our private decryption key
     * @param decryptionKeyStoreFilePassword password for said filestore
     * @param decryptionKeyAlias             alias for private decryption key
     * @param decryptionKeyPassword          password for private decryption key
     * @return decrypter to use or null id either we've no metadata for decryption or missing keystore details
     */
    public static Decrypter setupDecrypter(final String encryptionAlgorithm,
                                     InputStream decryptionKeyStoreFileStream,
                                     final String decryptionKeyStoreFilePassword,
                                     final String decryptionKeyAlias,
                                     final String decryptionKeyPassword) {
        if (encryptionAlgorithm != null && decryptionKeyStoreFileStream != null
                && decryptionKeyStoreFilePassword != null && decryptionKeyAlias != null
                && decryptionKeyPassword != null) {
            final KeyStoreCredentialHandler keyStoreCredentialHandler =
                    new KeyStoreCredentialHandler(decryptionKeyStoreFileStream, decryptionKeyStoreFilePassword);
            final BasicCredential privateCredentials = keyStoreCredentialHandler.getPrivateCredentials(decryptionKeyAlias, decryptionKeyPassword);
            KeyInfoCredentialResolver kekResolver = new StaticKeyInfoCredentialResolver(privateCredentials);
            ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver();
            encryptedKeyResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
            encryptedKeyResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
            encryptedKeyResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());
            return new Decrypter(null, kekResolver, encryptedKeyResolver);
        } else {
            return null;
        }
    }

    /**
     * Setup the SAML2 decrypter if we were given the full set of private key details
     *
     * @param encryptionAlgorithm            encryption algorithm name or null
     * @param decryptionKeyStoreFilePath     file path for keystore holding our private decryption key
     * @param decryptionKeyStoreFilePassword password for said filestore
     * @param decryptionKeyAlias             alias for private decryption key
     * @param decryptionKeyPassword          password for private decryption key
     * @return decrypter to use or null id either we've no metadata for decryption or missing keystore details
     */
    public static Decrypter setupDecrypter(final String encryptionAlgorithm,
                                     final String decryptionKeyStoreFilePath,
                                     final String decryptionKeyStoreFilePassword,
                                     final String decryptionKeyAlias,
                                     final String decryptionKeyPassword) {
        if (encryptionAlgorithm != null && decryptionKeyStoreFilePath != null
                && decryptionKeyStoreFilePassword != null && decryptionKeyAlias != null
                && decryptionKeyPassword != null) {
            final KeyStoreCredentialHandler keyStoreCredentialHandler =
                    new KeyStoreCredentialHandler(decryptionKeyStoreFilePath, decryptionKeyStoreFilePassword);
            final BasicCredential privateCredentials = keyStoreCredentialHandler.getPrivateCredentials(decryptionKeyAlias, decryptionKeyPassword);
            KeyInfoCredentialResolver kekResolver = new StaticKeyInfoCredentialResolver(privateCredentials);
            ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver();
            encryptedKeyResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
            encryptedKeyResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
            encryptedKeyResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());
            return new Decrypter(null, kekResolver, encryptedKeyResolver);
        } else {
            return null;
        }
    }
}
