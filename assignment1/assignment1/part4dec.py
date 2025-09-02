import subprocess
import json
import os

key_lengths = [128, 192, 256]
modes = ["ecb", "cbc", "ctr", "gcm"]
input_files = [
    "1.txt",
    "100.txt",
    "1024.txt",
    "102400.txt",
    "104857600.txt"
]



results = []
os.makedirs("decrypted", exist_ok=True)

for key in key_lengths:
    for mode in modes:
        cipher_spec = f"aes-{key}-{mode}"
        for infile in input_files:
            infile = f"outputs/{infile}_{key}_{mode}.txt"
            # Generate an output file name based on input file, key, and mode
            outfile_name = os.path.basename(infile)
            outfile = f"decrypted/{outfile_name}_{key}_{mode}.txt"
            
            # garbage output (can change if wanted) cause if no -out it prints to stdout
            args_str = f'dec -in {infile} -out garbage.txt -key key_{key}.base64 -iv iv.base64 -cipher {cipher_spec}'
            cmd = ['gradle', 'run', '--args', args_str]
            
            print(f"Running: {infile}-{cipher_spec}")
            
            try:
                # Run Gradle command
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                # Print stdout for debugging
                print(result.stdout)
                
                # Parse encryption time from stdout
                time_ms = None
                for line in result.stdout.splitlines():
                    if "Decryption time:" in line:
                        time_ms = float(line.split(":")[1].strip().split()[0])
                        break
                
                # Append results
                if time_ms is not None:
                    results.append({
                        "key_length": key,
                        "mode": mode,
                        "input_file": infile,
                        "output_file": outfile,
                        "decryption_time_ms": time_ms
                    })
                else:
                    results.append({
                        "key_length": key,
                        "mode": mode,
                        "input_file": infile,
                        "output_file": outfile,
                        "error": "Encryption time not found in output"
                    })
                    
            except Exception as e:
                results.append({
                    "key_length": key,
                    "mode": mode,
                    "input_file": infile,
                    "output_file": outfile,
                    "error": str(e)
                })

# Save all results to JSON
with open("timing_results2.json", "w") as f:
    json.dump(results, f, indent=2)

print("Results saved to timing_results2.json")
