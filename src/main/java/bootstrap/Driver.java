package bootstrap;

import com.google.protobuf.ByteString;
import encryption.EncryptionUtil;
import encryption.KeyStoreUtil;
import space.exploration.communications.protocol.communication.RoverStatusOuterClass;
import space.exploration.communications.protocol.security.SecureMessage;
import util.LoggerUtil;
import util.TrackedLogger;
import util.UUIdSingleton;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

public class Driver {
    public static final int NUM_ITERATIONS = 5;
    public static final String SEPARATOR =
            "==============================================================";
    public static File clientCertificate = new File("src/main/resources/encryptionKeys/client.ser");
    public static File serverCertificate = new File("src/main/resources/encryptionKeys/server.ser");

    public static void main(String[] args) {
        LoggerUtil.configureConsoleLogging(Boolean.parseBoolean(args[0]), UUIdSingleton.getInstance().uuid);
        TrackedLogger logger = new TrackedLogger(Driver.class);
        logger.info(SEPARATOR);
        logger.info("Start of benchmark test. Courtesy ---> M O R P H E U S ");
        try {
            double totalTime = 0l;
            for (int i = 0; i < NUM_ITERATIONS; i++) {
                logger.info("Running processor benchmark for file = " + args[0] + " iteration = " + i);
                totalTime += runTimedTest(logger, args[0]);
            }
            logger.info("Average time = " + totalTime / NUM_ITERATIONS + " seconds.");
        } catch (Exception e) {
            logger.error("Benchmarking test failed.", e);
        }
        logger.info("End of test.");
        logger.info(SEPARATOR);
    }

    public static Properties getProjectProperties(String propertiesFilePath) throws IOException {
        FileInputStream projFile = new FileInputStream(propertiesFilePath);
        Properties properties = new Properties();
        properties.load(projFile);
        return properties;
    }

    public static RoverStatusOuterClass.RoverStatus composeStatusMessage(byte[] content) {
        RoverStatusOuterClass.RoverStatus.Builder rBuilder = RoverStatusOuterClass.RoverStatus.newBuilder();
        rBuilder.setSolNumber(100);
        rBuilder.setModuleMessage(ByteString.copyFrom(content));
        rBuilder.setNotes("This is a test with a secret message.");
        return rBuilder.build();
    }

    public static long runTimedTest(TrackedLogger logger, String filePath) throws Exception {
        long startTimeMs = System.currentTimeMillis();
        byte[] originalContent = Files.readAllBytes(Paths.get(filePath));
        SecureMessage.SecureMessagePacket secureMessagePacket = EncryptionUtil.encryptData("test",
                serverCertificate, composeStatusMessage(originalContent).toByteArray(), 1l);
        byte[] decryptedContent = EncryptionUtil.decryptSecureMessage(clientCertificate, secureMessagePacket, 1l);
        RoverStatusOuterClass.RoverStatus roverStatus =
                RoverStatusOuterClass.RoverStatus.parseFrom(decryptedContent);
        byte[] retrievedContent = roverStatus.getModuleMessage().toByteArray();
        boolean comparison = originalContent.equals(retrievedContent);
        logger.info("Content comparison = " + comparison);
        return TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis() - startTimeMs);
    }
}
