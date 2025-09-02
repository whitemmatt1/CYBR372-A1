import os
import random
import string

sizes = [
    1, 10, 100, 1024,         # 1B, 10B, 100B, 1KB
    10*1024, 100*1024,        # 10KB, 100KB
    1*1024*1024, 10*1024*1024, 100*1024*1024  # 1MB, 10MB, 100MB
]

os.makedirs("inputs2", exist_ok=True)

letters = string.ascii_letters  # a-zA-Z

for size in sizes:
    filename = f"inputs/{size}.txt"
    # Generate random letters as a string
    content = ''.join(random.choices(letters, k=size))
    with open(filename, "w") as f:  # open in text mode
        f.write(content)
    print(f"Created {filename} ({size} bytes)")
