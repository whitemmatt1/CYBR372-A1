package assignment1.crypto;

import assignment1.cli.ArgumentBundle;
import assignment1.cli.StatusCode;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class Decryptor {

    public static int run(ArgumentBundle args) {
        try {
            if (args.getInputFile() == null) {
                System.err.println("Error: Missing required -in argument.");
                return StatusCode.INVALID_ARGUMENTS;
            }
            Path inPath = Path.of(args.getInputFile());
            if (!Files.exists(inPath)) {
                System.err.println("Error: Input file does not exist: " + args.getInputFile());
                return StatusCode.FILE_NOT_FOUND;
            }

            CipherUtils.Result<Cipher> cRes = CipherUtils.buildCipher(args, Cipher.DECRYPT_MODE);
            if (!cRes.ok()) return cRes.code;
            Cipher cipher = cRes.value;

            InputStream rawIn = Files.newInputStream(inPath);
            OutputStream out = (args.getOutputFile() != null)
                    ? Files.newOutputStream(Path.of(args.getOutputFile()))
                    : System.out;

            try (var in = rawIn;
                 var cis = new CipherInputStream(in, cipher);
                 var o = out) {

                byte[] buf = new byte[8192];
                int r;
                while ((r = cis.read(buf)) != -1) {
                    o.write(buf, 0, r);
                }
            }

            return StatusCode.SUCCESS;
        } catch (java.nio.file.NoSuchFileException e) {
            System.err.println("Error: File not found: " + e.getFile());
            return StatusCode.FILE_WRITE_ERROR;
        } catch (Exception e) {
            System.err.println("Error: Decryption failed: " + e.getMessage());
            return StatusCode.DECRYPTION_ERROR;
        }
    }
}
