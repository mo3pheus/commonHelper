package domain;

import space.exploration.communications.protocol.security.SecureMessage;

import java.io.Serializable;

public class SecureResult implements Serializable {
    private byte[] data;
    private int    blockId;

    public byte[] getData() {
        return data;
    }

    public int getBlockId() {
        return blockId;
    }

    public SecureResult(byte[] data, int blockId) {
        this.blockId = blockId;
        this.data = data;
    }
}
