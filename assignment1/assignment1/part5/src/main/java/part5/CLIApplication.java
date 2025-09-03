package part5;

import java.nio.file.*;
import java.util.HashMap;
import java.util.Map;

public class CLIApplication {

    public static int run(String[] args) {
        try {
            if (args.length != 10) {
                System.err.println("Usage: java Part5 -ct <ciphertext> -pt <knownplaintext> -iv <iv.base64> -salt <salt.base64> -cipher <cipher>");
                return StatusCode.ARGUMENT_ERROR;
            }

            Map<String, String> a = parseArgs(args);
            for (String k : new String[]{"-ct", "-pt", "-iv", "-salt", "-cipher"}) {
                if (!a.containsKey(k) || a.get(k) == null) {
                    System.err.println("Missing required argument: " + k);
                    return StatusCode.ARGUMENT_ERROR;
                }
            }

            // Basic file existence checks
            if (!Files.isRegularFile(Paths.get(a.get("-ct")))) { System.err.println("Ciphertext file not found"); return StatusCode.FILE_ERROR; }
            if (!Files.isRegularFile(Paths.get(a.get("-pt")))) { System.err.println("Plaintext file not found");  return StatusCode.FILE_ERROR; }
            if (!Files.isRegularFile(Paths.get(a.get("-iv")))) { System.err.println("IV file not found");         return StatusCode.FILE_ERROR; }
            if (!Files.isRegularFile(Paths.get(a.get("-salt")))) { System.err.println("Salt file not found");     return StatusCode.FILE_ERROR; }

            BruteForceBreaker.Result res = BruteForceBreaker.bruteforce(
                    Paths.get(a.get("-ct")),
                    Paths.get(a.get("-pt")),
                    Paths.get(a.get("-iv")),
                    Paths.get(a.get("-salt")),
                    a.get("-cipher").toLowerCase().trim()
            );

            if (res.status == StatusCode.SUCCESS) {
                // Print ONLY the PIN on stdout (tests capture this)
                System.out.println(res.pin);
            } else if (res.status == StatusCode.PIN_NOT_FOUND) {
                // Don't print a PIN to stdout; be gentle on stderr
                System.err.println("PIN not found in 0000–9999.");
            }

            return res.status;

        } catch (IllegalArgumentException e) {
            System.err.println("Argument error: " + e.getMessage());
            return StatusCode.ARGUMENT_ERROR;
        } catch (java.nio.file.NoSuchFileException e) {
            System.err.println("File error: " + e.getMessage());
            return StatusCode.FILE_ERROR;
        } catch (Exception e) {
            // Any other unexpected failure should not crash
            System.err.println("Unexpected error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return StatusCode.UNKNOWN_ERROR;
        }
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < args.length; i += 2) {
            String key = args[i];
            String val = (i + 1 < args.length) ? args[i + 1] : null;
            m.put(key, val);
        }
        return m;
    }
}
