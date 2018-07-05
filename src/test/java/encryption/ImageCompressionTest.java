package encryption;

import com.google.protobuf.ByteString;
import junit.framework.TestCase;
import org.junit.Test;
import space.exploration.communications.protocol.communication.RoverStatusOuterClass;
import space.exploration.communications.protocol.security.SecureMessage;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ImageCompressionTest extends TestCase {
    final String SEPARATOR      = "=============================================================================";
    final String THIN_SEPARATOR = "-----------------------------------------------------------------------------";
    final String VERTICAL_SEPERATOR = "|";
    File clientCertificate   = new File("src/main/resources/encryptionKeys/client.ser");
    File                              serverCertificate   = new File("src/main/resources/encryptionKeys/server.ser");
    File                              imageFile           = new File("src/main/resources/data/img.png");
    SecureMessage.SecureMessagePacket secureMessagePacket = null;
    RoverStatusOuterClass.RoverStatus roverStatus         = null;


    private String constructOutput(String fileType, String algorithm, boolean isCompressionEnabled, long time) {
        String out = String.format(" %10s ", fileType);
        out += VERTICAL_SEPERATOR;
        out += String.format(" %16s ", algorithm);
        out += VERTICAL_SEPERATOR;
        if(!isCompressionEnabled) {
            out += String.format(" %18s ", "No");
        } else {
            out += String.format(" %18s ", "Yes");
        }
        out += VERTICAL_SEPERATOR;
        out += " " + time;
        return out;
    }

    @Override
    public void setUp() throws IOException {
        RoverStatusOuterClass.RoverStatus.Builder rBuilder = RoverStatusOuterClass.RoverStatus.newBuilder();
        rBuilder.setSolNumber(100);
        byte[] content = Files.readAllBytes(Paths.get(imageFile.getPath()));
        rBuilder.setModuleMessage(ByteString.copyFrom(content));
        rBuilder.setNotes("This is a test with a secret image message.");
        roverStatus = rBuilder.build();
        System.out.println("     Sample | Algorithm Choice | compressionEnabled | timeInMilliseconds");
    }

    @Test
    public void testImageCompressionEnabled() {
        try {
            long start = System.currentTimeMillis();

            secureMessagePacket = EncryptionUtil.encryptData("Server", serverCertificate,
                    roverStatus.toByteArray(), 1, true);

            assertTrue(roverStatus.toByteArray().length >= secureMessagePacket.getContentLength());

            byte[] decryptedContent = EncryptionUtil.decryptSecureMessage
                    (clientCertificate, secureMessagePacket, 1, true);
            long stop = System.currentTimeMillis();

            assertEquals(roverStatus.toByteArray().length, decryptedContent.length);

            String output = constructOutput("Image", "Parallel", true,
                    stop - start);
            System.out.println(output);
            RoverStatusOuterClass.RoverStatus roverStatusNew = RoverStatusOuterClass.RoverStatus.parseFrom
                    (decryptedContent);
            assertEquals(roverStatusNew, roverStatus);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testImageCompressionDisabled() {
        try {
            long start = System.currentTimeMillis();

            secureMessagePacket = EncryptionUtil.encryptData("Server", serverCertificate,
                    roverStatus.toByteArray(), 1, false);

            assertEquals(roverStatus.toByteArray().length, secureMessagePacket.getContentLength());

            byte[] decryptedContent = EncryptionUtil.decryptSecureMessage
                    (clientCertificate, secureMessagePacket, 1, false);
            long stop = System.currentTimeMillis();

            assertEquals(roverStatus.toByteArray().length, decryptedContent.length);


            String output = constructOutput("Image", "Parallel", false,
                    stop - start);
            System.out.println(output);
            RoverStatusOuterClass.RoverStatus roverStatusNew = RoverStatusOuterClass.RoverStatus.parseFrom
                    (decryptedContent);
            assertEquals(roverStatusNew, roverStatus);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
