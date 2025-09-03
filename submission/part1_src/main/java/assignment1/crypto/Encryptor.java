package assignment1.crypto;

import assignment1.cli.ArgumentBundle;
import assignment1.cli.StatusCode;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class Encryptor {

    public static int run(ArgumentBundle args) {
        try {
            // Basic input presence check
            if (args.getInputFile() == null) {
                System.err.println("Error: Missing required -in argument.");
                return StatusCode.INVALID_ARGUMENTS;
            }
            Path inPath = Path.of(args.getInputFile());
            if (!Files.exists(inPath)) {
                System.err.println("Error: Input file does not exist: " + args.getInputFile());
                return StatusCode.FILE_NOT_FOUND;
            }

            // Build cipher
            CipherUtils.Result<Cipher> cRes = CipherUtils.buildCipher(args, Cipher.ENCRYPT_MODE);
            if (!cRes.ok()) return cRes.code;
            Cipher cipher = cRes.value;

            // Output stream
            OutputStream rawOut = (args.getOutputFile() != null)
                    ? Files.newOutputStream(Path.of(args.getOutputFile()))
                    : System.out;

            try (var in = Files.newInputStream(inPath);
                 var out = rawOut;
                 var cos = new CipherOutputStream(out, cipher)) {

                // Stream data; supports empty files as well
                byte[] buf = new byte[8192];
                int r;
                while ((r = in.read(buf)) != -1) {
                    cos.write(buf, 0, r);
                }
            }

            return StatusCode.SUCCESS;
        } catch (java.nio.file.NoSuchFileException e) {
            System.err.println("Error: File not found: " + e.getFile());
            return StatusCode.FILE_WRITE_ERROR;
        } catch (Exception e) {
            System.err.println("Error: Encryption failed: " + e.getMessage());
            return StatusCode.FILE_WRITE_ERROR;
        }
    }
}
