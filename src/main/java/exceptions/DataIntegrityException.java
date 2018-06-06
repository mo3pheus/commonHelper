package exceptions;

public class DataIntegrityException extends Exception {
    private String exceptionMessage;

    public DataIntegrityException(String exceptionMessage) {
        this.exceptionMessage = exceptionMessage;
    }

    @Override
    public String getMessage() {
        return exceptionMessage;
    }
}
