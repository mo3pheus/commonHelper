package encryption;

import com.google.protobuf.ByteString;
import com.sun.xml.internal.messaging.saaj.util.ByteInputStream;
import junit.framework.TestCase;
import space.exploration.communications.protocol.communication.RoverStatusOuterClass;
import space.exploration.communications.protocol.security.SecureMessage;
import sun.misc.IOUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.Test;

public class EncryptionOperationsTest extends TestCase {

    File                              clientCertificate   = new File("src/main/resources/encryptionKeys/client.ser");
    File                              serverCertificate   = new File("src/main/resources/encryptionKeys/server.ser");
    File                              imageFile           = new File("src/main/resources/data/telemetry.ser");
    SecureMessage.SecureMessagePacket secureMessagePacket = null;
    RoverStatusOuterClass.RoverStatus roverStatus         = null;
    byte[]                            rawData             = null;

    @Override
    public void setUp() throws IOException, ClassNotFoundException {
        byte[] content = Files.readAllBytes(Paths.get(imageFile.getPath()));
        roverStatus = RoverStatusOuterClass.RoverStatus.parseFrom(content);
    }

    @Test
    public void testEncryptionData() {
        try {
            secureMessagePacket = EncryptionUtil.encryptData("Server",
                                                             serverCertificate,
                                                             roverStatus
                                                                     .toByteArray());
            rawData = roverStatus.toByteArray();
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
