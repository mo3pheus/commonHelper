package common;

import com.google.protobuf.ByteString;
import compression.CompressionUtil;
import encryption.EncryptionUtil;
import junit.framework.TestCase;
import org.junit.Test;
import space.exploration.communications.protocol.communication.RoverStatusOuterClass;
import space.exploration.communications.protocol.propulsion.TelemetryDataOuterClass;
import space.exploration.communications.protocol.security.SecureMessage;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class EncryptionWithCompressionTest extends TestCase {
    final String SEPARATOR      = "=============================================================================";
    final String THIN_SEPARATOR = "-----------------------------------------------------------------------------";
    File clientCertificate   = new File("src/main/resources/encryptionKeys/client.ser");
    File                              serverCertificate   = new File("src/main/resources/encryptionKeys/server.ser");
    File                              imageFile           = new File("src/main/resources/data/telemetry.ser");
    SecureMessage.SecureMessagePacket secureMessagePacket = null;
    RoverStatusOuterClass.RoverStatus roverStatus         = null;
    byte[] compressedContent                              = null;

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
    public void testDataEncryptionWithCompression() {
        try {
            long start = System.currentTimeMillis();
            secureMessagePacket = EncryptionUtil.encryptData("Server", serverCertificate,
                    CompressionUtil.compress(roverStatus.toByteArray()), 1);
            byte[] decryptedContent = EncryptionUtil.decryptSecureMessage
                    (clientCertificate, secureMessagePacket, 1);
            System.out.println("Time taken for decryption = " + (System.currentTimeMillis() - start));
            System.out.println("Decrypted Length: " + decryptedContent.length);
            RoverStatusOuterClass.RoverStatus roverStatusNew = RoverStatusOuterClass.RoverStatus.parseFrom
                    (CompressionUtil.decompress(decryptedContent));
            System.out.println(SEPARATOR);
            System.out.println("Data Encryption With Compression Test");
            System.out.println(roverStatus);
            TelemetryDataOuterClass.TelemetryData telemetryData = TelemetryDataOuterClass.TelemetryData.parseFrom
                    (roverStatus.getModuleMessage().toByteArray());
            System.out.println(THIN_SEPARATOR);
            System.out.println(telemetryData);
            System.out.println(THIN_SEPARATOR);
            System.out.println(SEPARATOR);
            assertTrue(roverStatusNew.equals(roverStatus));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
