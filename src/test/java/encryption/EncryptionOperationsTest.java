package encryption;

import com.google.protobuf.ByteString;
import com.sun.xml.internal.messaging.saaj.util.ByteInputStream;
import junit.framework.TestCase;
import org.junit.Ignore;
import space.exploration.communications.protocol.communication.RoverStatusOuterClass;
import space.exploration.communications.protocol.security.SecureMessage;
import sun.misc.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.junit.Test;

public class EncryptionOperationsTest extends TestCase {

    File                              clientCertificate   = new File("src/main/resources/encryptionKeys/client.ser");
    File                              serverCertificate   = new File("src/main/resources/encryptionKeys/server.ser");
    File                              imageFile           = new File("src/main/resources/data/telemetry.ser");
    SecureMessage.SecureMessagePacket secureMessagePacket = null;
    RoverStatusOuterClass.RoverStatus roverStatus         = null;

    @Override
    public void setUp() throws IOException {
        RoverStatusOuterClass.RoverStatus.Builder rBuilder = RoverStatusOuterClass.RoverStatus.newBuilder();

        rBuilder.setSolNumber(100);

        FileInputStream fileInputStream = new FileInputStream(imageFile);
        byte[] content = null;



        rBuilder.setNotes("This is a test with a secret message.");
        roverStatus = rBuilder.build();
    }

    @Ignore
    public void testEncryptionData() {
        try {
            secureMessagePacket = EncryptionUtil.encryptData("Server",
                                                             serverCertificate,
                                                             roverStatus
                                                                     .toByteArray());
            byte[] decryptedContent = EncryptionUtil.decryptContent(clientCertificate,
                                                                    secureMessagePacket);
            RoverStatusOuterClass.RoverStatus roverStatusNew = RoverStatusOuterClass.RoverStatus.parseFrom
                    (decryptedContent);
            assertTrue(roverStatusNew.equals(roverStatus));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testNewDataEncryption() {
        try {
            secureMessagePacket = EncryptionUtil.encryptData("Server", serverCertificate, roverStatus.toByteArray());
            byte[]                            decryptedContent = EncryptionUtil.decryptSecureMessage
                    (clientCertificate, secureMessagePacket);
            RoverStatusOuterClass.RoverStatus roverStatus      = RoverStatusOuterClass.RoverStatus.parseFrom
                    (decryptedContent);
            System.out.println(roverStatus);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
