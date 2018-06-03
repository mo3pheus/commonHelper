package util;

import java.util.UUID;

public class UUIdSingleton {
    public               UUID          uuid          = UUID.randomUUID();
    private static final UUIdSingleton uuIdInstance  = new UUIdSingleton();

    private UUIdSingleton() {

    }

    public static synchronized UUIdSingleton getInstance() {
        return uuIdInstance;
    }
}
