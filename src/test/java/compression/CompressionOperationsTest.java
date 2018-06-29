package compression;

import com.google.protobuf.ByteString;
import junit.framework.TestCase;
import org.junit.Test;
import space.exploration.communications.protocol.communication.RoverStatusOuterClass;
import space.exploration.communications.protocol.security.SecureMessage;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class CompressionOperationsTest extends TestCase {
    final String SEPARATOR      = "=============================================================================";
    final String THIN_SEPARATOR = "-----------------------------------------------------------------------------";
    File                              imageFile           = new File("src/main/resources/data/telemetry.ser");
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
    public void testDataCompression() {
        try {
            long start;
            long stop;
            byte[] content = roverStatus.toByteArray();
            start = System.currentTimeMillis();
            byte[] compressedContent = CompressionUtil.compress(content);
            stop = System.currentTimeMillis();
            System.out.println(SEPARATOR);
            System.out.println("Data Compression Test");
            System.out.println(THIN_SEPARATOR);
            System.out.println("Size before compression: " + content.length);
            System.out.println("Size after compression: " + compressedContent.length);
            System.out.println(THIN_SEPARATOR);
            System.out.println("Time taken for compression: " + (stop - start));
            start = System.currentTimeMillis();
            byte[] decompressedContent = CompressionUtil.decompress(compressedContent);
            RoverStatusOuterClass.RoverStatus roverStatusNew = RoverStatusOuterClass.RoverStatus.parseFrom
                    (decompressedContent);
            stop = System.currentTimeMillis();
            System.out.println("Time taken for decompression: " + (stop - start));
            System.out.println(THIN_SEPARATOR);
            System.out.println(SEPARATOR);
            assertTrue(roverStatusNew.equals(roverStatus));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
