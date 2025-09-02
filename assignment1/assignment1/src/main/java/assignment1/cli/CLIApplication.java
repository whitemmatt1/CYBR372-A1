package assignment1.cli;

import assignment1.crypto.Encryptor;
import assignment1.crypto.Decryptor;
import java.nio.file.Files;
import java.nio.file.Path;



public class CLIApplication {

    public static int run(String[] argv) {
        ArgumentBundle args = ArgumentParser.parse(argv);
        if (args == null) {
            return StatusCode.INVALID_ARGUMENTS;
        }

        // Validation rules
        if (args.getInputFile() == null) {
            System.err.println("Error: Missing required input file");
            return StatusCode.INVALID_ARGUMENTS;
        }
        if (!Files.exists(Path.of(args.getInputFile()))) {
            System.err.println("Error: Input file does not exist: " + args.getInputFile());
            return StatusCode.FILE_NOT_FOUND;
        }
        if (args.getKeyFile() == null && args.getPassword() == null) {
            System.err.println("Error: Must provide either -key or -pass with -salt");
            return StatusCode.INVALID_ARGUMENTS;
        }

        if (args.getPassword() != null && args.getSaltFile() == null) {
            System.err.println("Error: -pass requires -salt");
            return StatusCode.INVALID_ARGUMENTS;
        }

        if (!args.getCipherSpec().contains("ecb") && args.getIvFile() == null) {
            System.err.println("Error: -iv is required for non-ECB ciphers");
            return StatusCode.INVALID_ARGUMENTS;
        }

        ArgumentBundle.Operation op = args.getOperation();

        if (op == ArgumentBundle.Operation.ENCRYPT) {
            long startTime = System.nanoTime();
            int result = Encryptor.run(args);
            long endTime = System.nanoTime();
            double elapsedMillis = (endTime - startTime) / 1_000_000.0;
            System.out.printf("Encryption time: %.3f ms%n", elapsedMillis);
            return result;
        } else if (op == ArgumentBundle.Operation.DECRYPT) {
            long startTime = System.nanoTime();
            int result = Decryptor.run(args);
            long endTime = System.nanoTime();
            double elapsedMillis = (endTime - startTime) / 1_000_000.0;
            System.out.printf("Decryption time: %.3f ms%n", elapsedMillis);
            return result;
        } else {
            System.err.println("Error: Unknown operation (must be 'enc' or 'dec')");
            return StatusCode.INVALID_ARGUMENTS;
        }
    }

}
