package certificates;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RsaSecureComsCertificate implements Serializable {
    private static final long       serialVersionUID = 1L;
    private              PublicKey  signaturePubKey  = null;
    private              PublicKey  messagePubKey    = null;
    private              PrivateKey signaturePrvKey  = null;
    private              PrivateKey messagePrvKey    = null;
    private              String     senderId         = null;

    public PublicKey getSignaturePubKey() {
        return signaturePubKey;
    }

    public void setSignaturePubKey(PublicKey signaturePubKey) {
        this.signaturePubKey = signaturePubKey;
    }

    public PublicKey getMessagePubKey() {
        return messagePubKey;
    }

    public void setMessagePubKey(PublicKey messagePubKey) {
        this.messagePubKey = messagePubKey;
    }

    public PrivateKey getSignaturePrvKey() {
        return signaturePrvKey;
    }

    public void setSignaturePrvKey(PrivateKey signaturePrvKey) {
        this.signaturePrvKey = signaturePrvKey;
    }

    public PrivateKey getMessagePrvKey() {
        return messagePrvKey;
    }

    public void setMessagePrvKey(PrivateKey messagePrvKey) {
        this.messagePrvKey = messagePrvKey;
    }

    public String getSenderId() {
        return senderId;
    }

    public void setSenderId(String senderId) {
        this.senderId = senderId;
    }
}
