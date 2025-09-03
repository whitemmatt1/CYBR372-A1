## CYBR372 Assignment 1 

### Part 1
Part 1 is a Java AES File Encryptor/Decryptor in which I was given a skeleton file structure and test cases that needed to be passed which was used for grading.

```bash
java Assignment1 enc|dec -in <file> [-out <file>] [-pass <password>] [-salt <salt.base64>] [-key <key.base64>] [-iv <iv.base64>] [-cipher <cipher>]
```

### Part 2
Part 2 posed a question whether my application would be vunerable to a padding oracle attack considering this example wrapper:

```bash
#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path

# Path to the internal Base64 key
INTERNAL_KEY_FILE = Path("internal-key.base64").resolve()

def main():
    java_args = ["java", "-cp", "build/classes/java/main", "assignment1.Assignment1", "dec"]

    # Copy user arguments, skip any "-key" if provided
    skip_next = False
    for arg in sys.argv[1:]:
        if skip_next:
            skip_next = False
            continue
        if arg == "-key":
            skip_next = True
            continue
        java_args.append(arg)

    # Inject internal key
    java_args.extend(["-key", str(INTERNAL_KEY_FILE)])

    try:
        # Call Java CLI and forward stdout/stderr
        result = subprocess.run(java_args, stdout=sys.stdout, stderr=sys.stderr)
        sys.exit(result.returncode)
    except Exception as e:
        print(f"Error running CLI: {e}", file=sys.stderr)
        sys.exit(-1)

if __name__ == "__main__":
    main()
```

### Part 3
Part 3 was a vulnerability analysis for ECB and CBC.

### Part 4
Part 4 was performance profiling where I implemented a way to record the encryption and decryption times for various key lengths, cipher modes and  input sizes. Recording them into a json file using python and used matplotlib to graph and present my findings.

### Part 5
Part 5 is a Java Brute Force Application, which performs a brute-force key search under these assumptions:

- The AES key was derived using PBKDF2 with HMAC-SHA256 (65536 iterations) from a 4-digit numeric password (0000 – 9999) and the provided salt, as in Part 1.
- The provided ciphertext (-ct) is the encryption of the given known plaintext (-pt) under that derived key, with the specified IV and cipher mode (e.g., aes-128-cbc).

### Part 6 
Part 6 is just a reflection on this brute force attack, as to why I was able to "break" AES.
