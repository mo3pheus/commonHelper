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

public class AudioCompressionTest extends TestCase {
    final String SEPARATOR      = "=============================================================================";
    final String THIN_SEPARATOR = "-----------------------------------------------------------------------------";
    final String VERTICAL_SEPERATOR = "|";
    File clientCertificate   = new File("src/main/resources/encryptionKeys/client.ser");
    File                              serverCertificate   = new File("src/main/resources/encryptionKeys/server.ser");
    File                              audioFile           = new File("src/main/resources/data/audio.mp3");
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
        byte[] imageContent = Files.readAllBytes(Paths.get(audioFile.getPath()));
        rBuilder.setModuleMessage(ByteString.copyFrom(imageContent));
        rBuilder.setNotes("This is a test with a secret audio message.");
        roverStatus = rBuilder.build();
        System.out.println("     Sample | Algorithm Choice | compressionEnabled | timeInMilliseconds");
    }

    @Test
    public void testAudioCompressionEnabled() {
        try {
            long start = System.currentTimeMillis();
            secureMessagePacket = EncryptionUtil.encryptData("Server", serverCertificate,
                    roverStatus.toByteArray(), 1);
            byte[] decryptedContent = EncryptionUtil.decryptSecureMessage
                    (clientCertificate, secureMessagePacket, 1);
            long stop = System.currentTimeMillis();
            String output = constructOutput("Audio", "Parallel", true,
                    stop - start);
            System.out.println(output);
            RoverStatusOuterClass.RoverStatus roverStatusNew = RoverStatusOuterClass.RoverStatus.parseFrom
                    (decryptedContent);
            assertTrue(roverStatusNew.equals(roverStatus));
        } catch (Exception e) {
            e.printStackTrace();
        }
        roverStatus = null;
    }

    @Test
    public void testAudioCompressionDisabled() {
        try {
            long start = System.currentTimeMillis();
            EncryptionUtil.disableCompression();
            secureMessagePacket = EncryptionUtil.encryptData("Server", serverCertificate,
                    roverStatus.toByteArray(), 1);
            byte[] decryptedContent = EncryptionUtil.decryptSecureMessage
                    (clientCertificate, secureMessagePacket, 1);
            long stop = System.currentTimeMillis();
            String output = constructOutput("Audio", "Parallel", false,
                    stop - start);
            System.out.println(output);
            RoverStatusOuterClass.RoverStatus roverStatusNew = RoverStatusOuterClass.RoverStatus.parseFrom
                    (decryptedContent);
            assertFalse(EncryptionUtil.COMPRESSION_ENABLED);
            assertTrue(roverStatusNew.equals(roverStatus));
        } catch (Exception e) {
            e.printStackTrace();
        }
        roverStatus = null;
    }
}
