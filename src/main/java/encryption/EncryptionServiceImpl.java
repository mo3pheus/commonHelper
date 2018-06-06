package encryption;

import com.google.protobuf.ByteString;

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
    public ByteString encrypt() throws Exception {
        return ByteString.copyFrom(EncryptionUtil.encryptMessage(certificate, content));
    }

    @Override
    public ByteString decrypt() throws Exception {
        return ByteString.copyFrom(EncryptionUtil.decryptMessage(certificate, content));
    }

    @Override
    public ByteString call() throws Exception {
        Thread.currentThread().setName("encrypt(" + encrypt + ")_" + Integer.toString(blockId));
        return (encrypt) ? encrypt() : decrypt();
    }
}
