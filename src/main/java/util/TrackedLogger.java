package util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

public class TrackedLogger {
    private Logger logger = null;
    private UUID   uUId   = null;

    public TrackedLogger(Class objectType) {
        logger = LoggerFactory.getLogger(objectType);
        this.uUId = UUIdSingleton.getInstance().uuid;
    }

    public void info(String message, Exception e) {
        logger.info("uUId = " + uUId + " " + message, e);
    }

    public void info(String message) {
        logger.info("uUId = " + uUId + " " + message);
    }

    public void debug(String message) {
        logger.debug("uUId = " + uUId + " " + message);
    }

    public void debug(String message, Exception e) {
        logger.debug("uUId = " + uUId + " " + message, e);
    }

    public void error(String message, Exception e) {
        logger.error("uUId = " + uUId + " " + message, e);
    }

    public void error(String message) {
        logger.error("uUId = " + uUId + " " + message);
    }

    public void warn(String message) {
        logger.warn(message);
    }

    public void warn(String message, Exception e) {
        logger.warn(message, e);
    }
}