package bootstrap;

import encryption.KeyStoreUtil;
import util.LoggerUtil;
import util.TrackedLogger;
import util.UUIdSingleton;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Properties;

public class Driver {
    public static final String SEPARATOR =
            "==============================================================";

    public static Properties projectProperties = new Properties();

    public static void main1(String[] args) {
        try {
            LoggerUtil.configureConsoleLogging(Boolean.parseBoolean(args[0]), UUIdSingleton.getInstance().uuid);
            TrackedLogger logger = new TrackedLogger(Driver.class);
            logger.info(" Project properties are loaded. Log file generated for this run = ");
            projectProperties = getProjectProperties(args[1]);
            KeyStoreUtil.testRsaEncryptionProtobuf();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Properties getProjectProperties(String propertiesFilePath) throws IOException {
        FileInputStream projFile   = new FileInputStream(propertiesFilePath);
        Properties      properties = new Properties();
        properties.load(projFile);
        return properties;
    }
}
