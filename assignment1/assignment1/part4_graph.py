import json
import matplotlib.pyplot as plt
from collections import defaultdict

# Load your JSON files
with open("timing_results.json") as f:
    encryption_data = json.load(f)

with open("timing_results2.json") as f:
    decryption_data = json.load(f)

# Combine all data
all_data = encryption_data + decryption_data

# Organize data for plotting
# Nested dict: times[key_length][mode][input_size] = time
encryption_times = defaultdict(lambda: defaultdict(list))
decryption_times = defaultdict(lambda: defaultdict(list))

for entry in all_data:
    key = entry["key_length"]
    mode = entry["mode"]
    infile = entry["input_file"]
    
    # Extract input size from filename (assumes it starts with number like '1024.txt')
    input_size = int(infile.split("/")[1].split(".")[0])
    
    if "encryption_time_ms" in entry:
        encryption_times[key][mode].append((input_size, entry["encryption_time_ms"]))
    if "decryption_time_ms" in entry:
        decryption_times[key][mode].append((input_size, entry["decryption_time_ms"]))

# Function to plot times
def plot_times(times_dict, title):
    plt.figure(figsize=(10, 6))
    for key_length, modes in times_dict.items():
        for mode, data in modes.items():
            # Sort by input size
            data_sorted = sorted(data, key=lambda x: x[0])
            sizes = [d[0] for d in data_sorted]
            times = [d[1] for d in data_sorted]
            plt.plot(sizes, times, marker='o', label=f"{key_length}-{mode}")
    
    plt.xscale("log")  # input sizes vary widely
    plt.xlabel("Input size (bytes, log scale)")
    plt.ylabel("Time (ms)")
    plt.title(title)
    plt.legend()
    plt.grid(True, which="both", ls="--")
    plt.tight_layout()
    plt.show()

# Plot encryption times
plot_times(encryption_times, "Encryption Times")

# Plot decryption times
plot_times(decryption_times, "Decryption Times")
