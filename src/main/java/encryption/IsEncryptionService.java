package encryption;

import com.google.protobuf.ByteString;

import java.util.concurrent.Callable;

public interface IsEncryptionService extends Callable<ByteString> {
    ByteString encrypt() throws Exception;

    ByteString decrypt() throws Exception;
}
