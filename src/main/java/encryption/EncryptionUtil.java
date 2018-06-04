package encryption;

import certificates.RsaSecureComsCertificate;
import space.exploration.communications.protocol.security.SecureMessage;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;

public class EncryptionUtil {
    public static boolean verifyMessage(File certificate, SecureMessage.SecureMessagePacket message) throws
            NoSuchProviderException, NoSuchAlgorithmException, IOException, ClassNotFoundException,
            InvalidKeyException, SignatureException {
        RsaSecureComsCertificate comsCertificate = extractCertificateObject(certificate);
        byte[]                   givenSignature  = message.getSignature().toByteArray();
        byte[]                   content         = message.getContent().toByteArray();

        Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
        sig.initVerify(comsCertificate.getSignaturePubKey());

        BufferedInputStream bufferedInputStream = new BufferedInputStream(new ByteArrayInputStream(content));
        byte[]              buffer              = new byte[1024];
        int                 len;
        while (bufferedInputStream.available() != 0) {
            len = bufferedInputStream.read(buffer);
            sig.update(buffer, 0, len);
        }
        bufferedInputStream.close();

        return sig.verify(givenSignature);
    }

    public static byte[] decryptMessage(File certificate, SecureMessage.SecureMessagePacket messagePacket) throws
            Exception {
        RsaSecureComsCertificate comsCertificate  = extractCertificateObject(certificate);
        byte[]                   encryptedContent = messagePacket.getContent().toByteArray();

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, comsCertificate.getMessagePrvKey());

        return cipher.doFinal(encryptedContent);
    }

    public static byte[] encryptMessage(File certificate, byte[] rawContent) throws Exception {
        RsaSecureComsCertificate comsCertificate = extractCertificateObject(certificate);
        Cipher                   cipher          = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, comsCertificate.getMessagePubKey());

        return cipher.doFinal(rawContent);
    }

    public static byte[] signMessage(File certificate, byte[] encryptedContent) throws Exception {
        RsaSecureComsCertificate comsCertificate = extractCertificateObject(certificate);
        Signature                dsa             = Signature.getInstance("SHA1withDSA", "SUN");
        dsa.initSign(comsCertificate.getSignaturePrvKey());

        BufferedInputStream bufin  = new BufferedInputStream(new ByteArrayInputStream(encryptedContent));
        byte[]              buffer = new byte[1024];
        int                 len;
        while ((len = bufin.read(buffer)) >= 0) {
            dsa.update(buffer, 0, len);
        }
        bufin.close();
        return dsa.sign();
    }

    private static RsaSecureComsCertificate extractCertificateObject(File certificateFile) throws IOException,
            ClassNotFoundException {
        FileInputStream          fileInputStream          = new FileInputStream(certificateFile);
        ObjectInputStream        objectInputStream        = new ObjectInputStream(fileInputStream);
        RsaSecureComsCertificate rsaSecureComsCertificate = (RsaSecureComsCertificate) objectInputStream.readObject();
        return rsaSecureComsCertificate;
    }
}
