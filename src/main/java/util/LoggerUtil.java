package util;

import biz.paluch.logging.gelf.log4j.GelfLogAppender;
import com.yammer.metrics.core.Histogram;
import org.apache.log4j.*;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

public class LoggerUtil {
    /**
     * Configures logging in a file. The logs appear in executionLogs/log_infoLevel_report_<timeStamp>.log
     *
     * @param debug debug level flag
     * @param uuid  uuid for tracking logs
     * @return
     */
    public static String configureFileLogging(boolean debug, UUID uuid) {
        FileAppender fa = new FileAppender();

        if (!debug) {
            fa.setThreshold(Level.toLevel(Priority.INFO_INT));
            fa.setFile("executionLogs/log_infoLevel_report_" + Long.toString(System.currentTimeMillis()) + ".log");
        } else {
            fa.setThreshold(Level.toLevel(Priority.DEBUG_INT));
            fa.setFile("executionLogs/log_debugLevel_report_" + Long.toString(System.currentTimeMillis()) + ".log");
        }

        fa.setLayout(new EnhancedPatternLayout("%-6d [%t] %-5p %c{1.} - %m%n"));

        fa.activateOptions();
        org.apache.log4j.Logger.getRootLogger().addAppender(fa);
        return fa.getFile();
    }

    /**
     * Configures logging in a file. The logs appear in executionLogs/log_infoLevel_report_<timeStamp>.log
     *
     * @param debug debug level flag
     * @param uuid  uuid for tracking logs
     * @return
     */
    public static String configureFileLogging(boolean debug, Long uuid) {
        FileAppender fa = new FileAppender();

        if (!debug) {
            fa.setThreshold(Level.toLevel(Priority.INFO_INT));
            fa.setFile("executionLogs/log_infoLevel_report_" + Long.toString(System.currentTimeMillis()) + ".log");
        } else {
            fa.setThreshold(Level.toLevel(Priority.DEBUG_INT));
            fa.setFile("executionLogs/log_debugLevel_report_" + Long.toString(System.currentTimeMillis()) + ".log");
        }

        fa.setLayout(new EnhancedPatternLayout("%-6d [%t] %-5p %c{1.} - %m%n"));

        fa.activateOptions();
        org.apache.log4j.Logger.getRootLogger().addAppender(fa);
        return fa.getFile();
    }

    /**
     * Configures the logging to write to a console
     *
     * @param debug debug level boolean flag
     * @param uuid  uuid for tracking logs
     */
    public static void configureConsoleLogging(boolean debug, UUID uuid) {
        ConsoleAppender consoleAppender = new ConsoleAppender();

        if (debug) {
            consoleAppender.setThreshold(Level.toLevel(Priority.DEBUG_INT));
        } else {
            consoleAppender.setThreshold(Level.toLevel(Priority.INFO_INT));
        }

        consoleAppender.setLayout(new EnhancedPatternLayout("%-6d [%t] %-5p %c{1.} - %m%n"));

        consoleAppender.activateOptions();
        org.apache.log4j.Logger.getRootLogger().addAppender(consoleAppender);
    }

    /**
     * Configures the logging to write to a console
     *
     * @param debug debug level boolean flag
     * @param uuid  uuid for tracking logs
     */
    public static void configureConsoleLogging(boolean debug, Long uuid) {
        ConsoleAppender consoleAppender = new ConsoleAppender();

        if (debug) {
            consoleAppender.setThreshold(Level.toLevel(Priority.DEBUG_INT));
        } else {
            consoleAppender.setThreshold(Level.toLevel(Priority.INFO_INT));
        }

        consoleAppender.setLayout(new EnhancedPatternLayout("%-6d [%t] %-5p %c{1.} - %m%n"));

        consoleAppender.activateOptions();
        org.apache.log4j.Logger.getRootLogger().addAppender(consoleAppender);
    }

    public static GelfLogAppender getGelfLogAppender() {
        GelfLogAppender gelfLogAppender = new GelfLogAppender();
        gelfLogAppender.setGraylogHost("127.0.0.1");
        gelfLogAppender.setPort(12201);
        gelfLogAppender.setOriginHost("antares-mainframe");
        gelfLogAppender.setThreshold(Level.ERROR);
        gelfLogAppender.setTimestampPattern("yyyy-MM-DD E HH:mm:ss z");
        gelfLogAppender.activateOptions();
        return gelfLogAppender;
    }

    public static FileAppender getFileLogAppender() {
        FileAppender fa = new FileAppender();
        fa.setThreshold(Level.toLevel(Priority.INFO_INT));
        fa.setFile("executionLogs/log_infoLevel_report_" + Long.toString(System.currentTimeMillis()) + ".log");
        fa.setLayout(new EnhancedPatternLayout("%-6d [%t] %-5p %c{1.} - %m%n"));
        fa.activateOptions();
        return fa;
    }

    /**
     * Captures the responseTime metrics in log as well as a metrics output file.
     *
     * @param logger                - an instance of TrackedLogger
     * @param responseTimeHistogram - histogram for responseTime
     * @throws IOException
     */
    public static void captureMetrics(TrackedLogger logger, Histogram responseTimeHistogram, Map<Integer, Integer>
            responseCodeHistogram) throws IOException {
        logger.info("================================================================================");
        logger.info("RESPONSE TIME HISTOGRAM");
        logger.info("Mean responseTime = " + responseTimeHistogram.mean());
        logger.info("Max responseTime = " + responseTimeHistogram.max());
        logger.info("Min responseTime = " + responseTimeHistogram.min());
        logger.info("Median = " + responseTimeHistogram.getSnapshot().getMedian());
        logger.info("98th percentile = " + responseTimeHistogram.getSnapshot().get98thPercentile());
        logger.info("75th percentile = " + responseTimeHistogram.getSnapshot().get75thPercentile());
        logger.info("================================================================================");
        for (Map.Entry<Integer, Integer> entry : responseCodeHistogram.entrySet()) {
            logger.info("Response Code = " + entry.getKey() + " Count = " + entry.getValue());
        }
    }
}