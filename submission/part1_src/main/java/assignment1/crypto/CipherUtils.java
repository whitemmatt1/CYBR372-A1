package assignment1.crypto;

import assignment1.cli.ArgumentBundle;
import assignment1.cli.StatusCode;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class CipherUtils {
    public static Result<Cipher> buildCipher(ArgumentBundle args, int jceMode) {
        // Parse cipher spec (e.g., aes-256-cbc)
        CipherSpec spec = parseCipherSpec(args.getCipherSpec());
        if (!spec.valid) {
            System.err.println("Error: Invalid cipher spec: " + args.getCipherSpec());
            return Result.error(StatusCode.UNSUPPORTED_CIPHER);
        }

        // Choose key material: key file has precedence over password
        byte[] keyBytes;
        if (args.getKeyFile() != null) {
            Result<byte[]> keyRes = readBase64File(args.getKeyFile());
            if (!Files.exists(Path.of(args.getKeyFile()))) {
                System.err.println("Error: Key file does not exist: " + args.getKeyFile());
                return Result.error(StatusCode.FILE_NOT_FOUND);
            }
            if (!keyRes.ok()) return Result.error(StatusCode.INVALID_KEY);
            keyBytes = keyRes.value;

            // Validate length matches spec
            if (keyBytes.length * 8 != spec.keyBits) {
                System.err.printf("Error: Key length (%d bits) does not match cipher spec (%d bits).%n",
                        keyBytes.length * 8, spec.keyBits);
                return Result.error(StatusCode.INVALID_KEY);
            }
        } else {
            // password path
            if (args.getPassword() == null) {
                System.err.println("Error: missing key (-key) or password (-pass).");
                return Result.error(StatusCode.INVALID_ARGUMENTS);
            }
            if (args.getSaltFile() == null) {
                System.err.println("Error: -pass requires -salt.");
                return Result.error(StatusCode.INVALID_ARGUMENTS);
            }
            Result<byte[]> saltRes = readBase64File(args.getSaltFile());
            if (!Files.exists(Path.of(args.getSaltFile()))) {
                System.err.println("Error: Salt file does not exist: " + args.getSaltFile());
                return Result.error(StatusCode.FILE_NOT_FOUND);
            }
            if (!saltRes.ok()) return Result.error(StatusCode.INVALID_SALT);
            byte[] salt = saltRes.value;

            if (salt.length != 8) {
                System.err.println("Error: Salt must be exactly 8 bytes (Base64 file decodes to 8 bytes).");
                return Result.error(StatusCode.INVALID_SALT);
            }

            Result<byte[]> derived = deriveKeyPBKDF2(args.getPassword(), salt, spec.keyBits);
            if (!derived.ok()) return Result.error(derived.code);
            keyBytes = derived.value;
        }

        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        // IV handling
        IvParameterSpec ivSpec = null;
        GCMParameterSpec gcmSpec = null;
        boolean needsIv = spec.mode != AesMode.ECB;

        if (needsIv) {
            if (args.getIvFile() == null) {
                // For ECB, we ignore IV; for others, IV is required by spec
                if (spec.mode != AesMode.ECB) {
                    System.err.println("Error: -iv is required for non-ECB ciphers.");
                    return Result.error(StatusCode.INVALID_ARGUMENTS);
                }
            } else {
                Result<byte[]> ivRes = readBase64File(args.getIvFile());
                if (!Files.exists(Path.of(args.getIvFile()))) {
                System.err.println("Error: Iv file does not exist: " + args.getIvFile());
                return Result.error(StatusCode.FILE_NOT_FOUND);
            }
                if (!ivRes.ok()) return Result.error(StatusCode.INVALID_IV);
                byte[] iv = ivRes.value;

                if (iv.length != 16) {
                    System.err.printf("Error: %s requires a 16-byte IV but got %d bytes%n", spec.mode, iv.length);
                    return Result.error(StatusCode.INVALID_IV);
                }

                if (spec.mode == AesMode.GCM) {
                    gcmSpec = new GCMParameterSpec(128, iv); // 128-bit tag
                } else {
                    ivSpec = new IvParameterSpec(iv);
                }
            }
        }

        // Build transformation & init Cipher
        String transformation = spec.transformation; // e.g., AES/CBC/PKCS5Padding
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            if (spec.mode == AesMode.ECB) {
                cipher.init(jceMode, key);
            } else if (spec.mode == AesMode.GCM) {
                if (gcmSpec == null) {
                    System.err.println("Error: Missing or invalid IV for GCM.");
                    return Result.error(StatusCode.INVALID_IV);
                }
                cipher.init(jceMode, key, gcmSpec);
            } else {
                if (ivSpec == null) {
                    System.err.println("Error: Missing or invalid IV for " + spec.mode.name() + ".");
                    return Result.error(StatusCode.INVALID_IV);
                }
                cipher.init(jceMode, key, ivSpec);
            }
            return Result.ok(cipher);
        } catch (GeneralSecurityException e) {
            System.err.println("Error: Failed to initialize cipher: " + e.getMessage());
            return Result.error(jceMode == Cipher.ENCRYPT_MODE ? StatusCode.ENCRYPTION_ERROR : StatusCode.DECRYPTION_ERROR);
        }
    }

    // PBKDF2 (HMAC-SHA256, 65536 iters) 
    public static Result<byte[]> deriveKeyPBKDF2(String password, byte[] salt, int keyBits) {
        try {
            SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, keyBits);
            byte[] key = kf.generateSecret(spec).getEncoded();
            return Result.ok(key);
        } catch (GeneralSecurityException e) {
            System.err.println("Error: PBKDF2 failed: " + e.getMessage());
            return Result.error(StatusCode.INVALID_ARGUMENTS);
        }
    }

    // Base64 file reader with validation 
    public static Result<byte[]> readBase64File(String pathStr) {
        try {
            Path p = Path.of(pathStr);
            if (!Files.exists(p)) {
                System.err.println("Error: File not found: " + pathStr);
                return Result.error(StatusCode.FILE_NOT_FOUND);
            }
            String b64 = Files.readString(p, StandardCharsets.UTF_8).trim();
            try {
                byte[] decoded = Base64.getDecoder().decode(b64);
                return Result.ok(decoded);
            } catch (IllegalArgumentException e) {
                System.err.println("Error: Invalid Base64 in file: " + pathStr);
                return Result.error(StatusCode.INVALID_ARGUMENTS);
            }
        } catch (Exception ioe) {
            System.err.println("Error: IO failure reading file: " + pathStr + " (" + ioe.getMessage() + ")");
            return Result.error(StatusCode.FILE_NOT_READABLE);
        }
    }

    // CipherSpec parsing 
    private enum AesMode { ECB, CBC, CFB, OFB, CTR, GCM }

    private static class CipherSpec {
        boolean valid;
        int keyBits;               // 128/192/256
        AesMode mode;
        String transformation;     // e.g., AES/CBC/PKCS5Padding

        CipherSpec(boolean valid) { this.valid = valid; }
    }

    private static CipherSpec parseCipherSpec(String spec) {
        if (spec == null || spec.isEmpty()) spec = "aes-256-cbc"; // default
        String s = spec.toLowerCase().trim();

        // Format: aes-<bits>-<mode>
        if (!s.startsWith("aes-") || s.split("-").length != 3) {
            return new CipherSpec(false);
        }
        String[] parts = s.split("-");
        int bits;
        try {
            bits = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return new CipherSpec(false);
        }
        if (bits != 128 && bits != 192 && bits != 256) return new CipherSpec(false);

        AesMode mode;
        try {
            mode = AesMode.valueOf(parts[2].toUpperCase());
        } catch (IllegalArgumentException e) {
            return new CipherSpec(false);
        }

        String xform;
        switch (mode) {
            case ECB:
                xform = "AES/ECB/PKCS5Padding";
                break;
            case CBC:
                xform = "AES/CBC/PKCS5Padding";
                break;
            case CFB:
            case OFB:
            case CTR:
                // Stream-like: do not pad
                xform = "AES/" + mode.name() + "/NoPadding";
                break;
            case GCM:
                xform = "AES/GCM/NoPadding";
                break;
            default:
                return new CipherSpec(false);
        }

        CipherSpec out = new CipherSpec(true);
        out.keyBits = bits;
        out.mode = mode;
        out.transformation = xform;
        return out;
    }

    // Small Result helper 
    public static class Result<T> {
        public final T value;
        public final int code;
        public final boolean success;

        private Result(T value, int code, boolean success) {
            this.value = value; this.code = code; this.success = success;
        }
        public static <T> Result<T> ok(T v) { return new Result<>(v, StatusCode.SUCCESS, true); }
        public static <T> Result<T> error(int code) { return new Result<>(null, code, false); }
        public boolean ok() { return success; }
    }
}
