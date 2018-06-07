package encryption;

import certificates.RsaSecureComsCertificate;
import com.google.protobuf.ByteString;
import domain.SecureResult;
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
import java.util.concurrent.*;

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

    public synchronized static SecureMessage.SecureMessagePacket encryptData(String senderId, File certificate,
                                                                             byte[] rawContent)
            throws Exception {
        long                                      start         = System.currentTimeMillis();
        SecureMessage.SecureMessagePacket.Builder sBuilder      = SecureMessage.SecureMessagePacket.newBuilder();
        int                                       contentLength = rawContent.length;
        sBuilder.setContentLength(contentLength);
        sBuilder.setSignature(ByteString.copyFrom(signMessage(certificate, rawContent)));
        sBuilder.setSenderId(senderId);
        sBuilder.setCheckSum(ByteString.copyFrom(generateHash(rawContent)));

        int numBlocks = (int) Math.ceil((double) contentLength / (double)
                ENCRYPTION_BLOCK_SIZE);
        List<IsEncryptionService> encryptionServices = new ArrayList<>(numBlocks);
        ExecutorService           executorService    = Executors.newFixedThreadPool(numBlocks);

        int j = 0;
        byte[] temp = (contentLength < ENCRYPTION_BLOCK_SIZE) ? new byte[contentLength] : new
                byte[ENCRYPTION_BLOCK_SIZE];

        int k = 0;
        for (int i = 0; i < contentLength; i++) {
            temp[j++] = rawContent[i];
            if (j == ENCRYPTION_BLOCK_SIZE || i == (contentLength - 1)) {
                j = 0;
                encryptionServices.add(k, new EncryptionServiceImpl(certificate, true, temp, k));
                k++;
            }
        }

        List<Future<SecureResult>> secureResults = executorService.invokeAll(encryptionServices);
        SecureResult[]             results       = new SecureResult[numBlocks];
        for (Future<SecureResult> secureResultFuture : secureResults) {
            SecureResult secureResult = secureResultFuture.get();
            results[secureResult.getBlockId()] = secureResult;
        }

        List<ByteString> blockchain = new ArrayList<>();
        for (int i = 0; i < results.length; i++) {
            blockchain.add(ByteString.copyFrom(results[i].getContent()));
        }

        sBuilder.addAllContent(blockchain);
        sBuilder.setProcessingTime(System.currentTimeMillis() - start);
        return sBuilder.build();
    }

    public synchronized static byte[] decryptContent(File certificate, SecureMessage.SecureMessagePacket
            secureMessagePacket) throws
            Exception {
        byte[]           reconstructedContent = new byte[(int) secureMessagePacket.getContentLength()];
        List<ByteString> encryptedContent     = secureMessagePacket.getContentList();

        List<IsEncryptionService> decryptionTasks = new ArrayList<>();
        for (int i = 0; i < encryptedContent.size(); i++) {
            ByteString encryptedByteString = encryptedContent.get(i);
            IsEncryptionService temp = new EncryptionServiceImpl(certificate, false,
                                                                 encryptedByteString.toByteArray(), i);
            decryptionTasks.add(temp);
        }

        List<Future<SecureResult>> decryptionResults = (Executors.newFixedThreadPool(secureMessagePacket
                                                                                             .getContentList().size()
        )).invokeAll(decryptionTasks);

        SecureResult[] decryptedContent = new SecureResult[secureMessagePacket.getContentList().size()];
        for (Future<SecureResult> resultFuture : decryptionResults) {
            SecureResult temp = resultFuture.get();
            decryptedContent[temp.getBlockId()] = temp;
        }

        int j = 0;
        for (int i = 0; i < decryptedContent.length; i++) {
            byte[] current = decryptedContent[i].getContent();
            for (byte singleByte : current) {
                reconstructedContent[j++] = singleByte;
                if (j == secureMessagePacket.getContentLength()) {
                    break;
                }
            }
        }

//        if (!verifyContentIntegrity(secureMessagePacket, reconstructedContent)) {
//            throw new Exception("Content integrity not verified, checksum mismatch");
//        }
//
//        if (!verifyMessage(certificate, secureMessagePacket.getSignature().toByteArray(), reconstructedContent)) {
//            throw new Exception("Content could not be verified with given sender. " + secureMessagePacket.getSenderId
//                    ());
//        }

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
