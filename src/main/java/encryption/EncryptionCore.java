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
    private String       operation       = "";

    public EncryptionCore(File comsCertificate, byte[] input, boolean encrypt, int blockId) {
        this.input = input;
        this.encrypt = encrypt;
        this.comsCertificate = comsCertificate;
        this.blockId = blockId;
        operation = (encrypt) ? "encryptionCore_" : "decryptionCore_";
    }

    @Override
    public SecureResult call() throws Exception {
        Thread.currentThread().setName(operation + blockId);
        byte[] output = (encrypt) ? EncryptionUtil.encryptMessage(comsCertificate, input) : EncryptionUtil
                .decryptMessage(comsCertificate, input);
        result = new SecureResult(output, blockId);
        return result;
    }

    public SecureResult getResult(){
        return result;
    }
}
