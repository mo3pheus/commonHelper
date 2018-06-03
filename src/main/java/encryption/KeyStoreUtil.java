package encryption;

import communications.protocol.ModuleDirectory;
import space.exploration.communications.protocol.InstructionPayloadOuterClass;
import sun.misc.IOUtils;
import util.TrackedLogger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class KeyStoreUtil {
    private static final String        SEPARATOR         =
            "===========================================================================";
    private static       TrackedLogger logger            = new TrackedLogger(KeyStoreUtil.class);
    private static final String        KEYSTORE_FILE     = "src/main/resources/encryptionKeys/keyStore.ser";
    private static final String        KEYSTORE_FILE_RSA = "src/main/resources/encryptionKeys/keyStoreRSA.ser";
    private static final String        DATAFILE          = "src/main/resources/data/TopSecret.txt";

    public static void saveSignatureKeyObject() throws Exception {
        KeyStoreCustom   keyStoreCustom   = null;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", "SUN");
        keyPairGenerator.initialize(1024, SecureRandom.getInstance("SHA1PRNG", "SUN"));

        keyStoreCustom = new KeyStoreCustom(keyPairGenerator.generateKeyPair());
        FileOutputStream   fos                = new FileOutputStream(KEYSTORE_FILE);
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(fos);
        objectOutputStream.writeObject(keyStoreCustom);
        objectOutputStream.close();
        fos.close();
    }

    public static void saveRsaKeyObject() throws Exception {
        KeyStoreCustom   keyStoreCustom   = null;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        keyStoreCustom = new KeyStoreCustom(keyPairGenerator.generateKeyPair());
        FileOutputStream   fos                = new FileOutputStream(KEYSTORE_FILE_RSA);
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(fos);
        objectOutputStream.writeObject(keyStoreCustom);
        objectOutputStream.close();
        fos.close();
    }

    public static void testKeyStore(String[] args) throws Exception {
        FileInputStream   fileInputStream   = new FileInputStream(new File(KEYSTORE_FILE));
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        KeyStoreCustom    keyStoreCustom    = (KeyStoreCustom) objectInputStream.readObject();

        PrivateKey privateKey = keyStoreCustom.getKeyPair().getPrivate();
        PublicKey  publicKey  = keyStoreCustom.getKeyPair().getPublic();

        logger.info(" Public = " + publicKey + " Private " + privateKey);

        Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
        dsa.initSign(privateKey);

        FileInputStream     fis    = new FileInputStream(DATAFILE);
        BufferedInputStream bufin  = new BufferedInputStream(fis);
        byte[]              buffer = new byte[1024];
        int                 len;
        while ((len = bufin.read(buffer)) >= 0) {
            dsa.update(buffer, 0, len);
        }
        ;
        bufin.close();
        byte[] realSig = dsa.sign();

        /* save the signature in a file */
        FileOutputStream sigfos = new FileOutputStream("sig");
        sigfos.write(realSig);
        sigfos.close();


        /* save the public key in a file */
        byte[]           key    = publicKey.getEncoded();
        FileOutputStream keyfos = new FileOutputStream("suepk");
        keyfos.write(key);
        keyfos.close();


        /* read the public key. */
        FileInputStream keyfis = new FileInputStream("suepk");
        byte[]          encKey = new byte[keyfis.available()];
        keyfis.read(encKey);

        keyfis.close();

        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
        KeyFactory         keyFactory = KeyFactory.getInstance("DSA", "SUN");
        PublicKey          pubKey     = keyFactory.generatePublic(pubKeySpec);

        FileInputStream sigfis      = new FileInputStream("sig");
        byte[]          sigToVerify = new byte[sigfis.available()];
        sigfis.read(sigToVerify);
        sigfis.close();

        Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
        sig.initVerify(pubKey);

        FileInputStream     datafis = new FileInputStream(DATAFILE);
        BufferedInputStream bufin1  = new BufferedInputStream(datafis);

        byte[] buffer1 = new byte[1024];
        int    len1;
        while (bufin1.available() != 0) {
            len1 = bufin1.read(buffer1);
            sig.update(buffer, 0, len1);
        }
        bufin1.close();

        boolean verifies = sig.verify(sigToVerify);

        logger.info("signature verifies: " + verifies);

        // get an DSA cipher object and print the provider
//        Cipher cipher = Cipher.getInstance("DSA/RSA/ECB/PKCS1Padding");
//        logger.info(cipher.getProvider().getInfo());
//
//        byte[] plainText = Files.readAllBytes(Paths.get(DATAFILE));
//        logger.info(SEPARATOR);
//        logger.info("Start of encryption");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] cipherText = cipher.doFinal(plainText);
//
//        logger.info("Finish encryption");
//        logger.info("Encrypted Text = " + new String(cipherText));
    }

    public static void testRsaEncryption() {
        try {
            logger.info(SEPARATOR);
            logger.info("Read keystore.");
            KeyStoreCustom rsaStore   = readKeyStore(KEYSTORE_FILE_RSA);
            PublicKey      publicKey  = rsaStore.getKeyPair().getPublic();
            PrivateKey     privateKey = rsaStore.getKeyPair().getPrivate();

            logger.info("Encrypt using public key");
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            logger.info(cipher.getProvider().getInfo());

            logger.info("Read plain text");
            byte[] plainText = Files.readAllBytes(Paths.get(DATAFILE));
            logger.info("Plain text = " + new String(plainText));

            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherText = cipher.doFinal(plainText);
            logger.info("Encrypted text = " + new String(cipherText, "UTF8"));

            // decrypt the ciphertext using the private key
            logger.info("Start decryption");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] newPlainText = cipher.doFinal(cipherText);
            logger.info("Finish decryption: ");
            logger.info(new String(newPlainText, "UTF8"));
            logger.info(SEPARATOR);
        } catch (IOException e) {
            logger.error("IOException ", e);
        } catch (ClassNotFoundException e) {
            logger.error("ClassNotFoundException ", e);
        } catch (NoSuchPaddingException e) {
            logger.error("Exception ", e);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Exception ", e);
        } catch (InvalidKeyException e) {
            logger.error("Exception ", e);
        } catch (BadPaddingException e) {
            logger.error("Exception ", e);
        } catch (IllegalBlockSizeException e) {
            logger.error("Exception ", e);
        }
    }

    public static void testRsaEncryptionProtobuf() {
        try {
            logger.info(SEPARATOR);
            logger.info("Read keystore.");
            KeyStoreCustom rsaStore   = readKeyStore(KEYSTORE_FILE_RSA);
            PublicKey      publicKey  = rsaStore.getKeyPair().getPublic();
            PrivateKey     privateKey = rsaStore.getKeyPair().getPrivate();

            logger.info("Encrypt using public key");
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            logger.info(cipher.getProvider().getInfo());

            logger.info("Read plain text");
            byte[] plainText = null;
            InstructionPayloadOuterClass.InstructionPayload.Builder iBuilder = InstructionPayloadOuterClass
                    .InstructionPayload.newBuilder();
            iBuilder.setTimeStamp(System.currentTimeMillis());
            iBuilder.setSOS(false);
            InstructionPayloadOuterClass.InstructionPayload.TargetPackage.Builder tBuilder =
                    InstructionPayloadOuterClass.InstructionPayload.TargetPackage.newBuilder();
            tBuilder.setRoverModule(ModuleDirectory.Module.CAMERA_SENSOR.getValue());
            tBuilder.setAction("Smile for the camera!");
            iBuilder.addTargets(tBuilder.build());
            plainText = iBuilder.build().toByteArray();
            logger.info("Plain text = " + new String(plainText, "UTF8"));

            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherText = cipher.doFinal(plainText);
            logger.info("Encrypted text = " + new String(cipherText, "UTF8"));

            // decrypt the ciphertext using the private key
            logger.info("Start decryption");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] newPlainText = cipher.doFinal(cipherText);
            InstructionPayloadOuterClass.InstructionPayload instructionPayload = InstructionPayloadOuterClass
                    .InstructionPayload.parseFrom(newPlainText);
            logger.info("Finish decryption: ");
            logger.info(instructionPayload.toString());

            logger.info(SEPARATOR);
        } catch (Exception e) {
            logger.error("IOException ", e);
        }
    }

    public static KeyStoreCustom readKeyStore(String fileName) throws IOException, ClassNotFoundException {
        FileInputStream   fileInputStream   = new FileInputStream(fileName);
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        KeyStoreCustom    keyStoreCustom    = (KeyStoreCustom) objectInputStream.readObject();
        return keyStoreCustom;
    }

    public static void readDataFile(String filename, Signature dsa) throws IOException, SignatureException {
        FileInputStream     fis    = new FileInputStream(filename);
        BufferedInputStream bufin  = new BufferedInputStream(fis);
        byte[]              buffer = new byte[1024];
        int                 len;
        while ((len = bufin.read(buffer)) >= 0) {
            dsa.update(buffer, 0, len);
        }
        bufin.close();
    }
}
