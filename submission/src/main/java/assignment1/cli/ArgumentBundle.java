package assignment1.cli;

public class ArgumentBundle {
    public enum Operation {ENCRYPT, DECRYPT}
     
    private Operation operation;
    private String inputFile;
    private String outputFile;
    private String password;
    private String saltFile;
    private String keyFile;
    private String ivFile;
    private String cipherSpec = "aes-256-cbc";

    public Operation getOperation() { return operation; }
    public void setOperation(Operation operation) { this.operation = operation; }

    public String getInputFile() { return inputFile; }
    public void setInputFile(String inputFile) { this.inputFile = inputFile; }

    public String getOutputFile() { return outputFile; }
    public void setOutputFile(String outputFile) { this.outputFile = outputFile; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getSaltFile() { return saltFile; }
    public void setSaltFile(String saltFile) { this.saltFile = saltFile; }

    public String getKeyFile() { return keyFile; }
    public void setKeyFile(String keyFile) { this.keyFile = keyFile; }

    public String getIvFile() { return ivFile; }
    public void setIvFile(String ivFile) { this.ivFile = ivFile; }

    public String getCipherSpec() { return cipherSpec; }
    public void setCipherSpec(String cipherSpec) { this.cipherSpec = cipherSpec; }
}
