package encryption;

import domain.SecureResult;

import java.util.concurrent.Callable;

public interface IsEncryptionService extends Callable<SecureResult> {
    SecureResult encrypt() throws Exception;

    SecureResult decrypt() throws Exception;
}
