package encryption;

import domain.SecureResult;

import java.io.File;
import java.util.concurrent.Callable;

public class EncryptionCore implements Callable<SecureResult> {
    private boolean      encrypt         = false;
    private byte[]       input           = null;
    private SecureResult result          = null;
    private File         comsCertificate = null;
    private int          blockId         = 0;

    public EncryptionCore(File comsCertificate, byte[] input, boolean encrypt, int blockId) {
        this.input = input;
        this.encrypt = encrypt;
        this.comsCertificate = comsCertificate;
        this.blockId = blockId;
    }

    @Override
    public SecureResult call() throws Exception {
        byte[] output = (encrypt) ? EncryptionUtil.encryptMessage(comsCertificate, input) : EncryptionUtil
                .decryptMessage(comsCertificate, input);
        result = new SecureResult(output, blockId);
        return result;
    }
}
