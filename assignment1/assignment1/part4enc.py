import subprocess
import json
import os

key_lengths = [128, 192, 256]
modes = ["ecb", "cbc", "ctr", "gcm"]
input_files = [
    "inputs/1.txt",
    "inputs/100.txt",
    "inputs/1024.txt",
    "inputs/102400.txt",
    "inputs/104857600.txt"
]

results = []
os.makedirs("outputs", exist_ok=True)

for key in key_lengths:
    for mode in modes:
        cipher_spec = f"aes-{key}-{mode}"
        for infile in input_files:
            # Generate an output file name based on input file, key, and mode
            outfile_name = os.path.basename(infile)
            outfile = f"outputs/{outfile_name}_{key}_{mode}.txt"
            
            args_str = f'enc -in {infile} -out {outfile} -key key_{key}.base64 -iv iv.base64 -cipher {cipher_spec}'
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
                    if "Encryption time:" in line:
                        time_ms = float(line.split(":")[1].strip().split()[0])
                        break
                
                # Append results
                if time_ms is not None:
                    results.append({
                        "key_length": key,
                        "mode": mode,
                        "input_file": infile,
                        "output_file": outfile,
                        "encryption_time_ms": time_ms
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
with open("timing_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("Results saved to timing_results.json")
