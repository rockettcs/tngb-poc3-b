package com.tngb.poc.usecase.utils;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Date;

public class Utils {

    /**
     * Loads a {@link KeyStore} from a file containing a private key, using the provided password.
     *
     * <p>This method loads a PKCS12 {@link KeyStore} from the specified file path. The method
     * attempts to read the keystore file, load it into a {@link KeyStore} instance, and then return
     * the populated {@link KeyStore} object.
     *
     * @param privateKeyPath the file path to the keystore containing the private key
     * @param privateKeyPassword the password used to protect the private key within the keystore
     * @return the loaded {@link KeyStore} containing the private key
     * @throws KeyStoreException if there is an issue with the {@link KeyStore} instance creation
     * @throws IOException if there is an error reading the keystore file
     * @throws NoSuchAlgorithmException if the algorithm used to check the integrity of the keystore cannot be found
     * @throws CertificateException if any of the certificates in the keystore could not be loaded
     * @see KeyStore
     * @see FileInputStream
     */
    public static KeyStore getKeyStore(String privateKeyPath, String privateKeyPassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream keystoreStream = new FileInputStream(privateKeyPath)) {
            keyStore.load(keystoreStream, privateKeyPassword.toCharArray());
        }
        return keyStore;
    }

    /**
     * Retrieves the private key from a keystore located at the specified file path.
     *
     * <p>This method loads a PKCS12 {@link KeyStore} from the provided file path, retrieves
     * the first alias in the keystore, and then uses that alias to obtain the private key
     * associated with it. The private key is returned if successfully retrieved.
     *
     * @param privateKeyPath the file path to the keystore containing the private key
     * @param privateKeyPassword the password used to protect the keystore and the private key within it
     * @return the {@link Key} object representing the private key
     * @throws KeyStoreException if there is an issue with the {@link KeyStore} instance creation or retrieval
     * @throws IOException if there is an error reading the keystore file
     * @throws UnrecoverableKeyException if the key cannot be recovered (e.g., due to an incorrect password)
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     * @throws CertificateException if any of the certificates in the keystore could not be loaded
     * @see KeyStore
     * @see Key
     */
    public static Key getKey(String privateKeyPath, String privateKeyPassword) throws KeyStoreException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = getKeyStore(privateKeyPath, privateKeyPassword);
        String alias = keyStore.aliases().nextElement();
        return keyStore.getKey(alias, privateKeyPassword.toCharArray());
    }

    /**
     * Retrieves the certificate from a keystore located at the specified file path.
     *
     * <p>This method loads a PKCS12 {@link KeyStore} from the provided file path, retrieves
     * the first alias in the keystore, and then uses that alias to obtain the certificate
     * associated with it. The certificate is returned if successfully retrieved.
     *
     * @param privateKeyPath the file path to the keystore containing the certificate
     * @param privateKeyPassword the password used to protect the keystore
     * @return the {@link Certificate} object representing the certificate
     * @throws KeyStoreException if there is an issue with the {@link KeyStore} instance creation or retrieval
     * @throws IOException if there is an error reading the keystore file
     * @throws NoSuchAlgorithmException if the algorithm for recovering the certificate cannot be found
     * @throws CertificateException if any of the certificates in the keystore could not be loaded
     * @see KeyStore
     * @see Certificate
     */
    public static Certificate getCertificate(String privateKeyPath, String privateKeyPassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = getKeyStore(privateKeyPath, privateKeyPassword);
        String alias = keyStore.aliases().nextElement();
        return (Certificate) keyStore.getCertificate(alias);
    }

    /**
     * Retrieves the private key from a keystore located at the specified file path.
     *
     * <p>This method loads a PKCS12 {@link KeyStore} from the provided file path and retrieves the private key
     * associated with the first alias in the keystore. It delegates the key retrieval to the {@link #getKey(String, String)}
     * method and casts the result to {@link PrivateKey}.
     *
     * @param privateKeyPath the file path to the keystore containing the private key
     * @param privateKeyPassword the password used to protect the keystore and the private key within it
     * @return the {@link PrivateKey} object representing the private key
     * @throws KeyStoreException if there is an issue with the {@link KeyStore} instance creation or retrieval
     * @throws IOException if there is an error reading the keystore file
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     * @throws CertificateException if any of the certificates in the keystore could not be loaded
     * @throws UnrecoverableKeyException if the key cannot be recovered (e.g., due to an incorrect password)
     * @see KeyStore
     * @see PrivateKey
     * @see #getKey(String, String)
     */
    public static PrivateKey getPrivateKey(String privateKeyPath, String privateKeyPassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        return (PrivateKey) getKey(privateKeyPath, privateKeyPassword);
    }

    /**
     * Retrieves the public key from a keystore located at the specified file path.
     *
     * <p>This method loads a PKCS12 {@link KeyStore} from the provided file path, retrieves the certificate
     * associated with the first alias in the keystore, and extracts the public key from that certificate.
     *
     * @param privateKeyPath the file path to the keystore containing the certificate and public key
     * @param privateKeyPassword the password used to protect the keystore
     * @return the {@link PublicKey} object representing the public key extracted from the certificate
     * @throws KeyStoreException if there is an issue with the {@link KeyStore} instance creation or retrieval
     * @throws IOException if there is an error reading the keystore file
     * @throws NoSuchAlgorithmException if the algorithm for recovering the public key cannot be found
     * @throws CertificateException if any of the certificates in the keystore could not be loaded
     * @see KeyStore
     * @see PublicKey
     * @see Certificate
     * @see #getCertificate(String, String)
     */
    public static PublicKey getPublicKey(String privateKeyPath, String privateKeyPassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        return getCertificate(privateKeyPath, privateKeyPassword).getPublicKey();
    }

    public static PublicKey getPublicKey(String publicKeyPath) throws FileNotFoundException, CertificateException {
        FileInputStream fis1 = new FileInputStream(publicKeyPath);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(fis1);
        return cert.getPublicKey();
    }

    /**
     * Generates a digital signature for the provided data using the specified private key.
     *
     * <p>This method utilizes the SHA-256 with RSA algorithm to create a signature for the
     * given data. The method initializes the {@link Signature} object in signing mode
     * with the provided private key, updates the signature with the data, and then signs
     * the data to produce a digital signature.
     *
     * @param data the data to be signed, represented as a byte array
     * @param key the private key used to sign the data. This key must be an instance of {@link PrivateKey}
     * @return a byte array containing the generated digital signature
     * @throws Exception if there is an issue with the signature generation, such as an invalid key or algorithm
     * @see Signature
     * @see PrivateKey
     */
    public static byte[] generateSignature(byte[] data, Key key) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign((PrivateKey) key);
        signer.update(data);
        return signer.sign();
    }

    /**
     * Verifies the digital signature of the provided data using the specified certificate.
     *
     * <p>This method utilizes the SHA-256 with RSA algorithm to verify that the provided
     * digital signature matches the expected signature for the given data. The method initializes
     * the {@link Signature} object in verification mode with the public key extracted from the
     * provided {@link Certificate}, updates the signature with the data, and then verifies
     * the signature.
     *
     * @param data the original data that was signed, represented as a byte array
     * @param signature the digital signature to be verified, represented as a byte array
     * @param certificate the certificate containing the public key used for verifying the signature
     * @return {@code true} if the signature is valid, {@code false} otherwise
     * @throws Exception if there is an issue with the signature verification, such as an invalid key, signature, or algorithm
     * @see Signature
     * @see Certificate
     */
    public static boolean verifySignature(byte[] data, byte[] signature, Certificate certificate) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(certificate.getPublicKey());
        verifier.update(data);
        return verifier.verify(signature);
    }

    /**
     * Creates an XML envelope containing the provided data, digital signature, and certificate.
     *
     * <p>This method constructs a simple XML structure with a root element named
     * <code>&lt;Envelope&gt;</code>. The XML document includes three child elements:
     * <code>&lt;OrgContent&gt;</code> for the original data, <code>&lt;Signature&gt;</code>
     * for the digital signature, and <code>&lt;Certificate&gt;</code> for the certificate.
     * The XML declaration is also included at the beginning of the envelope.
     *
     * @param data the original data to be included in the XML envelope
     * @param signature the digital signature corresponding to the data
     * @param certificate the certificate associated with the digital signature
     * @return a {@link String} containing the constructed XML envelope
     */
    public static String createXmlEnvelope(String data, String signature, String certificate) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\" ?>\n" +
                "<Envelope>\n" +
                "    <OrgContent>" + data + "</OrgContent>\n" +
                "    <Signature>" + signature + "</Signature>\n" +
                "    <Certificate>" + certificate + "</Certificate>\n" +
                "</Envelope>";
    }

    /**
     * Converts a standard Java {@link PrivateKey} to a {@link PGPPrivateKey} using the PGP library.
     *
     * <p>This method uses the {@link JcaPGPKeyConverter} to convert a standard Java {@link PrivateKey}
     * to a PGP-compatible {@link PGPPrivateKey}. The conversion requires a {@link PGPPublicKey} to associate
     * with the private key.
     *
     * @param privateKey the standard Java {@link PrivateKey} to be converted to PGP format
     * @param publicKey the {@link PGPPublicKey} associated with the private key, used for the conversion
     * @return the {@link PGPPrivateKey} object representing the converted private key
     * @throws PGPException if an error occurs during the conversion process
     * @see JcaPGPKeyConverter
     * @see PGPPrivateKey
     * @see PrivateKey
     * @see PGPPublicKey
     */
    public static PGPPrivateKey getPGPPrivateKey(PrivateKey privateKey, PGPPublicKey publicKey) throws PGPException {
        return new JcaPGPKeyConverter().getPGPPrivateKey(publicKey, privateKey);
    }

    /**
     * Converts a {@link PublicKey} object to a {@link PGPPublicKey} using the PGP library.
     *
     * <p>This method uses the {@link JcaPGPKeyConverter} to convert a standard Java {@link PublicKey}
     * to a PGP-compatible {@link PGPPublicKey}. The conversion specifies the RSA_GENERAL key type
     * and includes a timestamp for the key creation.
     *
     * @param publicKey the standard Java {@link PublicKey} to be converted to PGP format
     * @return the {@link PGPPublicKey} object representing the converted public key
     * @throws PGPException if an error occurs during the conversion process
     * @see JcaPGPKeyConverter
     * @see PGPPublicKey
     * @see PublicKey
     */
    public static PGPPublicKey getPGPPublicKey(PublicKey publicKey) throws PGPException {
        return new JcaPGPKeyConverter().getPGPPublicKey(PGPPublicKey.RSA_GENERAL, publicKey , new Date());
    }

    /**
     * Create an encrypted data blob using an AES-256 session key and the
     * passed in public key.
     *
     * @param encryptionKey the public key to use.
     * @param data the data to be encrypted.
     * @return a PGP binary encoded version of the encrypted data.
     */
    public static String encryptDataWithPGP(
            PGPPublicKey encryptionKey,
            byte[] data)
            throws PGPException, IOException
    {
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom()).setProvider("BC"));
        encGen.addMethod(
                new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey)
                        .setProvider("BC"));
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        // create an indefinite length encrypted stream
        OutputStream cOut = encGen.open(encOut, new byte[4096]);
        // write out the literal data
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(
                cOut, PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE, data.length, new Date());
        pOut.write(data);
        pOut.close();
        // finish the encryption
        cOut.close();
        return Base64.getEncoder().encodeToString(encOut.toByteArray());
    }

    /**
     * Extract the plain text data from the passed in encoding of PGP
     * encrypted data. The routine assumes the passed in private key
     * is the one that matches the first encrypted data object in the
     * encoding.
     *
     * @param privateKey the private key to decrypt the session key with.
     * @param pgpEncryptedData the encoding of the PGP encrypted data.
     * @return a byte array containing the decrypted data.
     */
    public static String decryptDataWithPGP(
            PGPPrivateKey privateKey,
            byte[] pgpEncryptedData)
            throws PGPException, IOException
    {
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpEncryptedData);
        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();
        // find the matching public key encrypted data packet.
        PGPPublicKeyEncryptedData encData = null;
        for (PGPEncryptedData pgpEnc: encList)
        {
            PGPPublicKeyEncryptedData pkEnc
                    = (PGPPublicKeyEncryptedData)pgpEnc;
            encData = pkEnc;
            break;
            /*if (pkEnc.getKeyID() == privateKey.getKeyID())
            {
                encData = pkEnc;
                break;
            }*/
        }
        /*if (encData == null)
        {
            throw new IllegalStateException("matching encrypted data not found");
        }*/
        // build decryptor factory
        PublicKeyDataDecryptorFactory dataDecryptorFactory =
                new JcePublicKeyDataDecryptorFactoryBuilder()
                        .setProvider("BC")
                        .build(privateKey);
        InputStream clear = encData.getDataStream(dataDecryptorFactory);
        byte[] literalData = Streams.readAll(clear);
        clear.close();
        // check data decrypts okay
        if (encData.verify())
        {
            // parse out literal data
            PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
            PGPLiteralData litData = (PGPLiteralData)litFact.nextObject();
            byte[] data = Streams.readAll(litData.getInputStream());
            return Strings.fromByteArray(data);
        }
        throw new IllegalStateException("modification check failed");
    }

}
