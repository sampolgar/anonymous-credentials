import matplotlib.pyplot as plt
import numpy as np
import os

# Create a directory for outputs
output_dir = 'plots'
os.makedirs(output_dir, exist_ok=True)

# Set style for academic visualization
plt.rcParams.update({
    'font.size': 12,
    'font.family': 'serif',
    'figure.figsize': (10, 6)
})

# Data from the LaTeX table (16 attributes per credential)
credential_counts = [4, 16, 32]

# Data for Single Issuer
single_baseline = [2.85, 10.03, 19.79]
single_verify = [7.28, 27.12, 54.00]
single_total = [12.28, 47.35, 94.10]

# Data for Multi Issuer
multi_baseline = [6.77, 27.69, 54.31]
multi_verify = [18.67, 76.52, 148.24]
multi_total = [25.08, 102.27, 199.87]

# Create two separate plots
# Plot 1: Single Issuer
plt.figure(figsize=(10, 6))
plt.plot(credential_counts, single_baseline, 'o-', color='green', linewidth=2, label='Signature Verify Baseline')
plt.plot(credential_counts, single_verify, 's--', color='blue', linewidth=2, label='Identity Binding Verify')
plt.plot(credential_counts, single_total, '^-.', color='red', linewidth=2, label='Identity Binding Show + Verify')

plt.title('Performance Comparison - Single Issuer (16 attributes per credential)')
plt.xlabel('Number of Credentials')
plt.ylabel('Execution Time (ms)')
plt.grid(True, alpha=0.3)
plt.legend(loc='best')
plt.xticks(credential_counts)

# Add values above data points
for i, count in enumerate(credential_counts):
    plt.text(count, single_baseline[i] + 1, f'{single_baseline[i]}', ha='center')
    plt.text(count, single_verify[i] + 2, f'{single_verify[i]}', ha='center')
    plt.text(count, single_total[i] + 3, f'{single_total[i]}', ha='center')

plt.tight_layout()
plt.savefig(f'{output_dir}/single_issuer_performance.png', dpi=300)
plt.savefig(f'{output_dir}/single_issuer_performance.pdf')
plt.close()

# Plot 2: Multi Issuer
plt.figure(figsize=(10, 6))
plt.plot(credential_counts, multi_baseline, 'o-', color='green', linewidth=2, label='Signature Verify Baseline')
plt.plot(credential_counts, multi_verify, 's--', color='blue', linewidth=2, label='Identity Binding Verify')
plt.plot(credential_counts, multi_total, '^-.', color='red', linewidth=2, label='Identity Binding Show + Verify')

plt.title('Performance Comparison - Multi Issuer (16 attributes per credential)')
plt.xlabel('Number of Credentials')
plt.ylabel('Execution Time (ms)')
plt.grid(True, alpha=0.3)
plt.legend(loc='best')
plt.xticks(credential_counts)

# Add values above data points
for i, count in enumerate(credential_counts):
    plt.text(count, multi_baseline[i] + 5, f'{multi_baseline[i]}', ha='center')
    plt.text(count, multi_verify[i] + 7, f'{multi_verify[i]}', ha='center')
    plt.text(count, multi_total[i] + 10, f'{multi_total[i]}', ha='center')

plt.tight_layout()
plt.savefig(f'{output_dir}/multi_issuer_performance.png', dpi=300)
plt.savefig(f'{output_dir}/multi_issuer_performance.pdf')
plt.close()

# Create a combined plot with both on same axes but using different marker styles
plt.figure(figsize=(12, 8))

# Single issuer plots with circular markers
plt.plot(credential_counts, single_baseline, 'o-', color='darkgreen', linewidth=2, markersize=8, label='Single Issuer - Signature Verify')
plt.plot(credential_counts, single_verify, 'o--', color='darkblue', linewidth=2, markersize=8, label='Single Issuer - Identity Binding Verify')
plt.plot(credential_counts, single_total, 'o-.', color='darkred', linewidth=2, markersize=8, label='Single Issuer - Identity Binding Total')

# Multi issuer plots with square markers
plt.plot(credential_counts, multi_baseline, 's-', color='lightgreen', linewidth=2, markersize=8, label='Multi Issuer - Signature Verify')
plt.plot(credential_counts, multi_verify, 's--', color='lightblue', linewidth=2, markersize=8, label='Multi Issuer - Identity Binding Verify')
plt.plot(credential_counts, multi_total, 's-.', color='salmon', linewidth=2, markersize=8, label='Multi Issuer - Identity Binding Total')

plt.title('Performance Comparison - All Implementations (16 attributes per credential)')
plt.xlabel('Number of Credentials')
plt.ylabel('Execution Time (ms)')
plt.grid(True, alpha=0.3)
plt.legend(loc='best')
plt.xticks(credential_counts)

plt.tight_layout()
plt.savefig(f'{output_dir}/combined_performance.png', dpi=300)
plt.close()

print("Graphs generated and saved to the 'plots' directory.")