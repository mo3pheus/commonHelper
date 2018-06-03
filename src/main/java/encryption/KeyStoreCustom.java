package encryption;

import java.io.Serializable;
import java.security.KeyPair;

public class KeyStoreCustom implements Serializable {
    private KeyPair keyPair;
    private static final long serialVersionUID = 1L;

    public KeyStoreCustom(KeyPair keyPair){
        this.keyPair = keyPair;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }
}