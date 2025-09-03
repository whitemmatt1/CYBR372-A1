package part5;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOut;
// import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOutNormalized;

// import java.io.*;
import java.nio.file.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class CLIApplicationTest {

    static final Path CIPHERTEXT_DIR = Paths.get("src", "test", "resources", "ciphertext");
    static final Path PLAINTEXT = Paths.get("src", "test", "resources", "plaintext.txt");
    static final Path SALT = Paths.get("src", "test", "resources", "salt.base64");
    static final Path IV = Paths.get("src", "test", "resources", "iv.base64");
    static final Path EXPECTED_PIN = Paths.get("src", "test", "resources", "expected", "pin.txt");


    static Stream<String> breakableFiles() {
        return Stream.of(
                "aes-128-cbc_from_PIN.enc",
                "aes-128-gcm_from_PIN.enc",
                "aes-128-ctr_from_PIN.enc",
                "aes-256-cbc_from_PIN.enc",
                "aes-256-ctr_from_PIN.enc",
                "aes-256-gcm_from_PIN.enc"
        );
    }

    // static Stream<String> unbreakableFiles() {
    //     return Stream.of(
    //             "aes-256-cbc_unbreakable.enc",
    //             "aes-256-gcm_unbreakable.enc"
    //     );
    // }

    @ParameterizedTest(name = "{0}")
    @MethodSource("breakableFiles")
    @DisplayName("Should recover correct PIN for breakable ciphertext")
    @Timeout(value = 600, unit = TimeUnit.SECONDS)
    void testBreakable(String ciphertextFile) throws Exception {
        Path ct = CIPHERTEXT_DIR.resolve(ciphertextFile);
        String cipher = ciphertextFile.replace("_from_PIN.enc", "");
        String expectedPin = Files.readString(EXPECTED_PIN).trim();

        String[] args = {
                "-ct", ct.toString(),
                "-pt", PLAINTEXT.toString(),
                "-iv", IV.toString(),
                "-salt", SALT.toString(),
                "-cipher", cipher
        };

        String output = tapSystemOut(() -> {
            int status = CLIApplication.run(args);
            assertEquals(StatusCode.SUCCESS, status, "Expected exit code for successful break");
        });

        assertEquals(expectedPin, output.trim(), "Expected the correct 4-digit PIN output");
    }

    // @ParameterizedTest(name = "{0}")
    // @MethodSource("unbreakableFiles")
    // @DisplayName("Should not recover PIN for unbreakable ciphertext")
    // @Timeout(value = 600, unit = TimeUnit.SECONDS)
    // void testUnbreakable(String ciphertextFile) throws Exception {
    //     Path ct = CIPHERTEXT_DIR.resolve(ciphertextFile);
    //     String cipher = ciphertextFile.replace("_unbreakable.enc", "");

    //     String[] args = {
    //         "-ct", ct.toString(),
    //         "-pt", PLAINTEXT.toString(),
    //         "-iv", IV.toString(),
    //         "-salt", SALT.toString(),
    //         "-cipher", cipher
    //     };

    //     String output = tapSystemOutNormalized(() -> {
    //         int status = CLIApplication.run(args);
    //         assertEquals(StatusCode.PIN_NOT_FOUND, status, "Expected PIN_NOT_FOUND status for unbreakable input");
    //     });

    //     assertTrue(
    //         output.isBlank()
    //         || output.toLowerCase().contains("not found")
    //         || output.toLowerCase().contains("no match"),
    //         "Expected no PIN output, but got: " + output
    //     );
    // }
}

