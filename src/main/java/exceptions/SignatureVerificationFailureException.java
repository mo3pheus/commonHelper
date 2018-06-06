package exceptions;

public class SignatureVerificationFailureException extends Exception {
    String message = null;

    public SignatureVerificationFailureException(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
