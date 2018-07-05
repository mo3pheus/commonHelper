package encryption;

import com.google.protobuf.ByteString;
import junit.framework.TestCase;
import org.junit.Ignore;
import space.exploration.communications.protocol.communication.RoverStatusOuterClass;
import space.exploration.communications.protocol.propulsion.TelemetryDataOuterClass;
import space.exploration.communications.protocol.security.SecureMessage;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.Test;

public class EncryptionOperationsTest extends TestCase {
    final String SEPARATOR      = "=============================================================================";
    final String THIN_SEPARATOR = "-----------------------------------------------------------------------------";
    File                              clientCertificate   = new File("src/main/resources/encryptionKeys/client.ser");
    File                              serverCertificate   = new File("src/main/resources/encryptionKeys/server.ser");
    File                              imageFile           = new File("src/main/resources/data/telemetry.ser");
    SecureMessage.SecureMessagePacket secureMessagePacket = null;
    RoverStatusOuterClass.RoverStatus roverStatus         = null;

    @Override
    public void setUp() throws IOException {
        RoverStatusOuterClass.RoverStatus.Builder rBuilder = RoverStatusOuterClass.RoverStatus.newBuilder();
        rBuilder.setSolNumber(100);
        byte[] content = Files.readAllBytes(Paths.get(imageFile.getPath()));
        rBuilder.setModuleMessage(ByteString.copyFrom(content));
        rBuilder.setNotes("This is a test with a secret message.");
        roverStatus = rBuilder.build();
    }

    @Test
    public void testNewDataEncryption() {
        try {
            long start = System.currentTimeMillis();
            secureMessagePacket = EncryptionUtil.encryptData("Server", serverCertificate,
                    roverStatus.toByteArray(), 1, false);
            byte[] decryptedContent = EncryptionUtil.decryptSecureMessage
                    (clientCertificate, secureMessagePacket, 1, false);
            System.out.println("Time taken for decryption = " + (System.currentTimeMillis() - start));
            RoverStatusOuterClass.RoverStatus roverStatusNew = RoverStatusOuterClass.RoverStatus.parseFrom
                    (decryptedContent);
            System.out.println(SEPARATOR);
            System.out.println(roverStatus);
            TelemetryDataOuterClass.TelemetryData telemetryData = TelemetryDataOuterClass.TelemetryData.parseFrom
                    (roverStatus.getModuleMessage().toByteArray());
            System.out.println(THIN_SEPARATOR);
            System.out.println(telemetryData);
            System.out.println(THIN_SEPARATOR);
            System.out.println(SEPARATOR);
            assertEquals(roverStatusNew, roverStatus);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
