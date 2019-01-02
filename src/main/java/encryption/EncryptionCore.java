package encryption;

import domain.SecureResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.concurrent.Callable;

public class EncryptionCore implements Callable<SecureResult> {
    private Logger  logger          = LoggerFactory.getLogger(EncryptionCore.class);
    private boolean encrypt         = false;
    private byte[]  input           = null;
    private File    comsCertificate = null;
    private int     blockId         = 0;
    private String  operation       = "";

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
        logger.debug("Work began for " + operation + blockId);
        byte[] output = null;
        try {
            output = (encrypt) ? EncryptionUtil.encryptMessage(comsCertificate, input) : EncryptionUtil
                    .decryptMessage(comsCertificate, input);
        } catch (Exception e) {
            logger.error("Exception while encrypt = " + encrypt + " id = " + blockId, e);
        }
        return new SecureResult(output, blockId);
    }
}
