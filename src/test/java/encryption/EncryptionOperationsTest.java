package encryption;

import com.google.protobuf.ByteString;
import junit.framework.TestCase;
import space.exploration.communications.protocol.communication.RoverStatusOuterClass;
import space.exploration.communications.protocol.security.SecureMessage;
import sun.misc.IOUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.junit.Test;

public class EncryptionOperationsTest extends TestCase {

    File                              clientCertificate   = new File("src/main/resources/encryptionKeys/client.ser");
    File                              serverCertificate   = new File("src/main/resources/encryptionKeys/server.ser");
    File                              imageFile           = new File("src/main/resources/data/image.jpg");
    SecureMessage.SecureMessagePacket secureMessagePacket = null;
    RoverStatusOuterClass.RoverStatus roverStatus         = null;

    @Override
    public void setUp() throws IOException {
        RoverStatusOuterClass.RoverStatus.Builder rBuilder = RoverStatusOuterClass.RoverStatus.newBuilder();

        rBuilder.setSolNumber(100);
        byte[] messageBytes = IOUtils.readFully(new FileInputStream(imageFile), 0, true);
        rBuilder.setModuleMessage(ByteString.copyFrom(messageBytes));
        rBuilder.setNotes("This is a test with a secret message.");
        roverStatus = rBuilder.build();
    }

    @Test
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
}
