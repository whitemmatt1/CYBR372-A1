package part5;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Objects;

public class BruteForceBreaker {

    public static class Result {
        public final int status;
        public final String pin;
        public Result(int status, String pin) { this.status = status; this.pin = pin; }
    }

    private static class CipherSpec {
        final int keyLenBits;
        final String mode;
        final String transformation;
        CipherSpec(int keyLenBits, String mode, String transformation) {
            this.keyLenBits = keyLenBits;
            this.mode = mode;
            this.transformation = transformation;
        }
    }

    /*
    * Attempt brute-force over PINs 0000..9999. On success, returns SUCCESS and the PIN; on failure PIN_NOT_FOUND.
    * Any I/O errors are thrown to caller for proper status handling.
    */
    public static Result bruteforce(Path ctPath, Path ptPath, Path ivB64Path, Path saltB64Path, String cipherString) throws Exception {
        byte[] ciphertext = Files.readAllBytes(ctPath);
        byte[] knownPlain  = Files.readAllBytes(ptPath);
        byte[] iv   = decodeBase64File(ivB64Path);
        byte[] salt = decodeBase64File(saltB64Path);

        CipherSpec spec = parseCipher(cipherString); // determines keyLen + mode + transformation
        if (spec.mode.equals("gcm")) {
            if (iv.length < 12) {
                throw new IllegalArgumentException("GCM requires a 12+ byte IV. Provided length: " + iv.length);
            }
        } else if (spec.mode.equals("cbc") || spec.mode.equals("ctr")) {
            if (iv.length != 16) {
                throw new IllegalArgumentException(spec.mode.toUpperCase() + " requires 16-byte IV. Provided length: " + iv.length);
            }
        }

        for (int pinNum = 0; pinNum <= 9999; pinNum++) {
            String pin = String.format("%04d", pinNum);
            try {
                SecretKeySpec key = deriveKey(pin.toCharArray(), salt, spec.keyLenBits);
                byte[] decrypted = tryDecrypt(ciphertext, key, iv, spec);

                // Compare to known plaintext
                if (decrypted != null && constantTimeEquals(decrypted, knownPlain)) {
                    return new Result(StatusCode.SUCCESS, pin);
                }
            } catch (AEADBadTagException badTag) {
            } catch (BadPaddingException | IllegalBlockSizeException wrongKey) {
            } catch (GeneralSecurityException e) {
            }
        }

        return new Result(StatusCode.PIN_NOT_FOUND, null);
    }


    private static byte[] decodeBase64File(Path p) throws Exception {
        String s = Files.readString(p).replaceAll("\\s+", "");
        return Base64.getDecoder().decode(s);
    }

    private static SecretKeySpec deriveKey(char[] password, byte[] salt, int keyLenBits)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final int iterations = 65536;
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLenBits);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] tryDecrypt(byte[] ciphertext, SecretKeySpec key, byte[] iv, CipherSpec spec)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(spec.transformation);
        switch (spec.mode) {
            case "gcm":
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
                cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec, new SecureRandom());
                break;
            case "cbc":
            case "ctr":
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
                break;
            default:
                throw new IllegalArgumentException("Unsupported mode: " + spec.mode);
        }
        return cipher.doFinal(ciphertext);
    }

    private static CipherSpec parseCipher(String s) {
        if (s == null) throw new IllegalArgumentException("Cipher string is null");
        String norm = s.toLowerCase().trim();

        // expects "aes-<key>-<mode>"
        String[] parts = norm.split("-");
        if (parts.length != 3 || !Objects.equals(parts[0], "aes")) {
            throw new IllegalArgumentException("Cipher must look like 'aes-128-cbc', got: " + s);
        }

        int keyBits;
        try {
            keyBits = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid AES key length in cipher: " + s);
        }
        if (keyBits != 128 && keyBits != 256) {
            throw new IllegalArgumentException("Unsupported AES key length: " + keyBits);
        }

        String mode = parts[2];
        switch (mode) {
            case "cbc":
                return new CipherSpec(keyBits, "cbc", "AES/CBC/PKCS5Padding");
            case "ctr":
                return new CipherSpec(keyBits, "ctr", "AES/CTR/NoPadding");
            case "gcm":
                return new CipherSpec(keyBits, "gcm", "AES/GCM/NoPadding");
            default:
                throw new IllegalArgumentException("Unsupported AES mode: " + mode);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int r = 0;
        for (int i = 0; i < a.length; i++) r |= (a[i] ^ b[i]);
        return r == 0;
    }
}
