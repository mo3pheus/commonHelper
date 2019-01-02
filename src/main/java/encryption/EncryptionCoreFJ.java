package encryption;

import domain.SecureResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.concurrent.ForkJoinTask;

public class EncryptionCoreFJ extends ForkJoinTask<SecureResult> {
    private Logger logger = LoggerFactory.getLogger(EncryptionCoreFJ.class);
    private boolean encrypt = false;
    private byte[] input = null;
    private File comsCertificate = null;
    private int blockId = 0;
    private String operation = "";
    private SecureResult result = null;

    @Override
    public SecureResult getRawResult() {
        return result;
    }

    @Override
    protected void setRawResult(SecureResult secureResult) {
        result = secureResult;
    }

    @Override
    protected boolean exec() {
        Thread.currentThread().setName(operation + blockId);
        logger.debug("Work began for " + operation + blockId);
        byte[] output = null;
        try {
            output = (encrypt) ? EncryptionUtil.encryptMessage(comsCertificate, input) : EncryptionUtil
                    .decryptMessage(comsCertificate, input);
        } catch (Exception e) {
            logger.error("Exception while encrypt = " + encrypt + " id = " + blockId, e);
            return false;
        }

        result = new SecureResult(output, blockId);
        return true;
    }

    public EncryptionCoreFJ(File comsCertificate, byte[] input, boolean encrypt, int blockId) {
        this.input = input;
        this.encrypt = encrypt;
        this.comsCertificate = comsCertificate;
        this.blockId = blockId;
        operation = (encrypt) ? "encryptionCore_" : "decryptionCore_";
    }
}
