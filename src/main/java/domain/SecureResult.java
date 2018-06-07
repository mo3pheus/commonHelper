package domain;

import java.io.Serializable;

public class SecureResult implements Serializable {
    byte[] content;
    int blockId;

    public SecureResult(byte[] content, int blockId){
        this.content = content;
        this.blockId = blockId;
    }

    public byte[] getContent() {
        return content;
    }

    public int getBlockId() {
        return blockId;
    }
}
