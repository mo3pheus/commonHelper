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

    public synchronized static RsaSecureComsCertificate extractCertificate(File certFile) throws IOException,
            ClassNotFoundException {
        FileInputStream          fileInputStream   = new FileInputStream(certFile);
        ObjectInputStream        objectInputStream = new ObjectInputStream(fileInputStream);
        RsaSecureComsCertificate comsCertificate   = (RsaSecureComsCertificate) objectInputStream.readObject();
        return comsCertificate;
    }

    public synchronized static boolean verifyMessage(File certificate, byte[] signatureToVerify, byte[] content)
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

    public synchronized static byte[] signMessage(File certificate, byte[] encryptedContent) throws Exception {
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

    public synchronized static byte[] encryptMessage(File certificate, byte[] rawContent) throws Exception {
        RsaSecureComsCertificate comsCertificate = extractCertificate(certificate);
        Cipher                   cipher          = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, comsCertificate.getMessagePubKey());
        return cipher.doFinal(rawContent);
    }

    public synchronized static byte[] decryptMessage(File certificate, byte[] encryptedContent) throws
            ClassNotFoundException,
            NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            NoSuchPaddingException, IOException {
        RsaSecureComsCertificate comsCertificate = extractCertificate(certificate);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, comsCertificate.getMessagePrvKey());
        return cipher.doFinal(encryptedContent);
    }

    public static SecureMessage.SecureMessagePacket encryptData(String senderId, File certificate, byte[] rawContent, long waitMinutes)
            throws Exception {
        long                                      start         = System.currentTimeMillis();
        SecureMessage.SecureMessagePacket.Builder sBuilder      = SecureMessage.SecureMessagePacket.newBuilder();
        int                                       contentLength = rawContent.length;
        sBuilder.setContentLength(contentLength);
        sBuilder.setSignature(ByteString.copyFrom(signMessage(certificate, rawContent)));
        sBuilder.setSenderId(senderId);
        sBuilder.setCheckSum(ByteString.copyFrom(generateHash(rawContent)));
        sBuilder.addAllContent(cutAndBoxData(certificate, contentLength, rawContent, waitMinutes));
        sBuilder.setProcessingTime(System.currentTimeMillis() - start);
        return sBuilder.build();
    }

    public static byte[] decryptSecureMessage(File certificate, SecureMessage.SecureMessagePacket
            secureMessagePacket, long waitMinutes) throws Exception {
        byte[][] decryptedContent = unpackAndDecryptData(certificate, secureMessagePacket, waitMinutes);
        byte[]   rawData          = stitchData(decryptedContent, (int) secureMessagePacket.getContentLength());
        if (verifyContentIntegrity(secureMessagePacket, rawData) && verifyMessage(certificate, secureMessagePacket
                .getSignature().toByteArray(), rawData)) {
            return rawData;
        } else {
            throw new Exception("Data integrity check failed. Unable to decrypt data. Sender id = " +
                                        secureMessagePacket.getSenderId());
        }
    }

    public synchronized static boolean verifyContentIntegrity(SecureMessage.SecureMessagePacket secureMessagePacket,
                                                              byte[]
                                                                      rawContent) throws NoSuchAlgorithmException {
        byte[] hash = generateHash(rawContent);
        return Arrays.equals(hash, secureMessagePacket.getCheckSum().toByteArray());
    }

    private synchronized static byte[] stitchData(byte[][] dataBlocks, int contentLength) {
        int    i            = 0;
        byte[] stitchedData = new byte[contentLength];

        for (byte[] temp : dataBlocks) {
            for (int j = 0; j < temp.length; j++) {
                stitchedData[i++] = temp[j];
                if (i == contentLength) {
                    break;
                }
            }
        }
        return stitchedData;
    }

    private synchronized static byte[] generateHash(byte[] content) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(content);
        return digest.digest();
    }

    private static byte[][] unpackAndDecryptData(File certificate, SecureMessage.SecureMessagePacket
            secureMessagePacket, long waitMinutes) throws ExecutionException, InterruptedException {
        int numBlocks = secureMessagePacket.getContentList().size();

        List<byte[]> encryptedBlockChain = new ArrayList<>();
        for (ByteString bytes : secureMessagePacket.getContentList()) {
            encryptedBlockChain.add(bytes.toByteArray());
        }

        List<EncryptionCore> encryptionCores = new ArrayList<>();
        for (int i = 0; i < encryptedBlockChain.size(); i++) {
            EncryptionCore decryptCore = new EncryptionCore(certificate, encryptedBlockChain.get(i), false, i);
            encryptionCores.add(decryptCore);
        }

        ExecutorService            decryptionService = Executors.newFixedThreadPool(numBlocks);
        List<Future<SecureResult>> futures           = decryptionService.invokeAll(encryptionCores);
        decryptionService.shutdown();
        decryptionService.awaitTermination(waitMinutes, TimeUnit.MINUTES);

        byte[][] decryptedContent = new byte[numBlocks][ENCRYPTION_BLOCK_SIZE];
        for (Future<SecureResult> future : futures) {
            SecureResult result = future.get();
            decryptedContent[result.getBlockId()] = result.getData();
        }

        return decryptedContent;
    }

    private static List<ByteString> cutAndBoxData(File certificate, int contentLength, byte[] rawContent, long
            waitMinutes) throws
            InterruptedException, ExecutionException {
        int numBlocks = (int) Math.ceil((double) contentLength / (double) ENCRYPTION_BLOCK_SIZE);

        int          blockSize   = (numBlocks > 1) ? ENCRYPTION_BLOCK_SIZE : contentLength;
        List<byte[]> inputChunks = new ArrayList<>();
        int          i           = 0;
        byte[]       temp        = new byte[blockSize];

        for (int j = 0; j < contentLength; j++) {
            temp[i++] = rawContent[j];

            if (i == blockSize || j == contentLength - 1) {
                inputChunks.add(temp);
                temp = new byte[blockSize];
                i = 0;
            }
        }

        List<EncryptionCore> encryptionCores   = new ArrayList<>();
        SecureResult[]       results           = new SecureResult[numBlocks];
        List<ByteString>     encryptedContents = new ArrayList<>();

        for (i = 0; i < numBlocks; i++) {
            encryptionCores.add(new EncryptionCore(certificate, inputChunks.get(i), true, i));
        }

        ExecutorService            encryptionService = Executors.newFixedThreadPool(numBlocks);
        List<Future<SecureResult>> futures           = encryptionService.invokeAll(encryptionCores);
        encryptionService.shutdown();
        encryptionService.awaitTermination(waitMinutes, TimeUnit.MINUTES);

        for (Future<SecureResult> future : futures) {
            SecureResult result = future.get();
            results[result.getBlockId()] = result;
        }

        for (i = 0; i < results.length; i++) {
            encryptedContents.add(ByteString.copyFrom(results[i].getData()));
        }

        return encryptedContents;
    }
}
