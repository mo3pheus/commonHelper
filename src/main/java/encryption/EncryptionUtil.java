package encryption;

import certificates.RsaSecureComsCertificate;
import com.google.protobuf.ByteString;
import exceptions.DataIntegrityException;
import exceptions.SignatureVerificationFailureException;
import space.exploration.communications.protocol.security.SecureMessage;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class EncryptionUtil {
    public static final int ENCRYPTION_BLOCK_SIZE = 2000;

    private static RsaSecureComsCertificate extractCertificate(File certFile) throws IOException,
            ClassNotFoundException {
        FileInputStream          fileInputStream   = new FileInputStream(certFile);
        ObjectInputStream        objectInputStream = new ObjectInputStream(fileInputStream);
        RsaSecureComsCertificate comsCertificate   = (RsaSecureComsCertificate) objectInputStream.readObject();
        return comsCertificate;
    }

    public static boolean verifyMessage(File certificate, byte[] signatureToVerify, byte[] content)
            throws InvalidKeyException, IOException, SignatureException, ClassNotFoundException,
            NoSuchProviderException, NoSuchAlgorithmException {
        RsaSecureComsCertificate comsCertificate = extractCertificate(certificate);
        Signature                signature       = Signature.getInstance("SHA1withDSA", "SUN");
        signature.initVerify(comsCertificate.getSignaturePubKey());

        BufferedInputStream bufin = new BufferedInputStream(new ByteArrayInputStream(content));

        byte[] buffer = new byte[10485760];
        int    len;
        while (bufin.available() != 0) {
            len = bufin.read(buffer);
            signature.update(buffer, 0, len);
        }
        bufin.close();

        return signature.verify(signatureToVerify);
    }

    public static byte[] signMessage(File certificate, byte[] encryptedContent) throws Exception {
        RsaSecureComsCertificate comsCertificate = extractCertificate(certificate);
        Signature                dsa             = Signature.getInstance("SHA1withDSA", "SUN");
        dsa.initSign(comsCertificate.getSignaturePrvKey());

        BufferedInputStream bufin  = new BufferedInputStream(new ByteArrayInputStream(encryptedContent));
        byte[]              buffer = new byte[10485760];
        int                 len;
        while ((len = bufin.read(buffer)) >= 0) {
            dsa.update(buffer, 0, len);
        }
        bufin.close();

        byte[] signature = dsa.sign();
        return signature;
    }

    public static byte[] encryptMessage(File certificate, byte[] rawContent) throws Exception {
        RsaSecureComsCertificate comsCertificate = extractCertificate(certificate);
        Cipher                   cipher          = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, comsCertificate.getMessagePubKey());
        return cipher.doFinal(rawContent);
    }

    public static byte[] decryptMessage(File certificate, byte[] encryptedContent) throws ClassNotFoundException,
            NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            NoSuchPaddingException, IOException {
        RsaSecureComsCertificate comsCertificate = extractCertificate(certificate);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, comsCertificate.getMessagePrvKey());
        return cipher.doFinal(encryptedContent);
    }

    public static SecureMessage.SecureMessagePacket encryptData(String senderId, File certificate, byte[] rawContent)
            throws Exception {
        long                                      start         = System.currentTimeMillis();
        SecureMessage.SecureMessagePacket.Builder sBuilder      = SecureMessage.SecureMessagePacket.newBuilder();
        int                                       contentLength = rawContent.length;
        sBuilder.setContentLength(contentLength);
        sBuilder.setSignature(ByteString.copyFrom(signMessage(certificate, rawContent)));
        sBuilder.setSenderId(senderId);
        sBuilder.setCheckSum(ByteString.copyFrom(generateHash(rawContent)));

        int              numBlocks  = (int) Math.ceil((double) contentLength / (double) ENCRYPTION_BLOCK_SIZE);
        List<ByteString> blockChain = new ArrayList<>(numBlocks);
        int              j          = 0;

        byte[] temp = null;
        if (contentLength < ENCRYPTION_BLOCK_SIZE) {
            temp = new byte[contentLength];
        } else {
            temp = new byte[ENCRYPTION_BLOCK_SIZE];
        }

        for (int i = 0; i < contentLength; i++) {
            temp[j++] = rawContent[i];
            if (j == ENCRYPTION_BLOCK_SIZE || i == (contentLength - 1)) {
                j = 0;
                blockChain.add(ByteString.copyFrom(encryptMessage(certificate, temp)));
            }
        }

        sBuilder.addAllContent(blockChain);
        sBuilder.setProcessingTime(System.currentTimeMillis() - start);
        return sBuilder.build();
    }

    public static byte[] decryptContent(File certificate, SecureMessage.SecureMessagePacket secureMessagePacket) throws
            DataIntegrityException, ClassNotFoundException, IOException, IllegalBlockSizeException,
            NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException, SignatureVerificationFailureException {
        long   listSize             = secureMessagePacket.getContentLength();
        byte[] reconstructedContent = new byte[(int) listSize];

        List<byte[]> contentList          = new ArrayList<>();
        int          encryptedContentSize = secureMessagePacket.getContentList().size();
        for (int i = 0; i < encryptedContentSize; i++) {
            contentList.add(decryptMessage(certificate, secureMessagePacket.getContentList().get(i).toByteArray()));
        }

        int i = 0;
        for (byte[] temp : contentList) {
            for (int j = 0; j < temp.length; j++) {
                reconstructedContent[i++] = temp[j];
                if (i == listSize) {
                    break;
                }
            }
        }

        if (!verifyContentIntegrity(secureMessagePacket, reconstructedContent)) {
            throw new DataIntegrityException("Content checkSum failed. SenderId = " + secureMessagePacket.getSenderId
                    ());
        }

        if (!verifyMessage(certificate, secureMessagePacket.getSignature().toByteArray(), reconstructedContent)) {
            throw new SignatureVerificationFailureException("Signature verification failed for senderId = " +
                                                                    secureMessagePacket.getSenderId());
        }

        return reconstructedContent;
    }

    public static boolean verifyContentIntegrity(SecureMessage.SecureMessagePacket secureMessagePacket, byte[]
            rawContent) throws NoSuchAlgorithmException {
        byte[] hash = generateHash(rawContent);
        return Arrays.equals(hash, secureMessagePacket.getCheckSum().toByteArray());
    }

    private static byte[] generateHash(byte[] content) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(content);
        return digest.digest();
    }
}
