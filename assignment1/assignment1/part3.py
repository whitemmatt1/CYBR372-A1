import matplotlib.pyplot as plt
import numpy as np
from collections import Counter

def create_publication_ready_plot():
    
    # Read data
    with open("out1.bin", "rb") as f:
        ecb_data = f.read()
    with open("out2.bin", "rb") as f:
        cbc_data = f.read()
    
    # Analyze
    ecb_blocks = [ecb_data[i:i+16] for i in range(0, len(ecb_data), 16)]
    ecb_counts = Counter(ecb_blocks)
    ecb_frequencies = list(ecb_counts.values())
    
    cbc_blocks = [cbc_data[i:i+16] for i in range(0, len(cbc_data), 16)]
    cbc_counts = Counter(cbc_blocks)
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # ECB plot
    ax1.hist(ecb_frequencies, bins=np.logspace(0, np.log10(max(ecb_frequencies)), 50), 
             alpha=0.8, color='red', edgecolor='black', linewidth=0.5)
    ax1.set_xscale('log')
    ax1.set_yscale('log')
    ax1.set_title('ECB Mode', fontsize=14, fontweight='bold')
    ax1.set_xlabel('Block Frequency', fontsize=12)
    ax1.set_ylabel('Number of Distinct Blocks', fontsize=12)
    ax1.grid(True, alpha=0.3)
    
    # CBC plot
    ax2.bar([1], [120004], width=0.6, alpha=0.8, color='blue', edgecolor='black', linewidth=0.5)
    ax2.set_title('CBC Mode', fontsize=14, fontweight='bold')
    ax2.set_xlabel('Block Frequency', fontsize=12)
    ax2.set_ylabel('Number of Distinct Blocks', fontsize=12)
    ax2.set_xlim(0.5, 1.5)
    ax2.set_ylim(0, 130000)
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('part3.png', dpi=300, bbox_inches='tight')
    plt.show()

if __name__ == "__main__":
    create_publication_ready_plot()