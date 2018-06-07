package encryption;

import domain.SecureResult;

import java.io.File;

public class EncryptionServiceImpl implements IsEncryptionService {
    File    certificate = null;
    boolean encrypt     = false;
    byte[]  content     = null;
    int     blockId     = 0;

    public EncryptionServiceImpl(File certificate, boolean encrypt, byte[] content, int blockId) {
        this.certificate = certificate;
        this.encrypt = encrypt;
        this.content = content;
        this.blockId = blockId;
    }

    @Override
    public SecureResult encrypt() throws Exception {
        return new SecureResult(EncryptionUtil.encryptMessage(certificate, content), blockId);
    }

    @Override
    public SecureResult decrypt() throws Exception {
        return new SecureResult(EncryptionUtil.decryptMessage(certificate, content), blockId);
    }

    @Override
    public SecureResult call() throws Exception {
        Thread.currentThread().setName("encrypt(" + encrypt + ")_" + Integer.toString(blockId));
        return (encrypt) ? encrypt() : decrypt();
    }
}
