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
    File                              imageFile           = new File
            ("src/main/resources/data/roverStatus_1543211971261.log");
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
            secureMessagePacket = EncryptionUtil.encryptData("Server", serverCertificate, roverStatus.toByteArray(), 1);
            byte[] decryptedContent = EncryptionUtil.decryptSecureMessage
                    (clientCertificate, secureMessagePacket, 1);
            System.out.println("Time taken for decryption New = " + (System.currentTimeMillis() - start));

            start = System.currentTimeMillis();
            secureMessagePacket = EncryptionUtil.encryptDataOld("Server", serverCertificate, roverStatus.toByteArray
                    (), 1);
            decryptedContent = EncryptionUtil.decryptSecureMessageOld
                    (clientCertificate, secureMessagePacket, 1);
            System.out.println("Time taken for decryption Old = " + (System.currentTimeMillis() - start));




            /*RoverStatusOuterClass.RoverStatus roverStatusNew = RoverStatusOuterClass.RoverStatus.parseFrom
                    (decryptedContent);
            System.out.println(SEPARATOR);
            System.out.println(roverStatus);
            TelemetryDataOuterClass.TelemetryData telemetryData = TelemetryDataOuterClass.TelemetryData.parseFrom
                    (roverStatus.getModuleMessage().toByteArray());
            System.out.println(THIN_SEPARATOR);
            System.out.println(telemetryData);
            System.out.println(THIN_SEPARATOR);
            System.out.println(SEPARATOR);
*/
            Thread.sleep(10000);

            //assertTrue(roverStatusNew.equals(roverStatus));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
