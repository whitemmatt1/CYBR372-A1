package part5;

public final class StatusCode {
    public static final int SUCCESS = 0;
    public static final int PIN_NOT_FOUND = -1;
    public static final int ARGUMENT_ERROR = 1;
    public static final int FILE_ERROR = 2;
    public static final int UNKNOWN_ERROR = 99;

    private StatusCode() {} 
}
