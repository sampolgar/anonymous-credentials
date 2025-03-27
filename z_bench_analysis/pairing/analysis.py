#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load the data from your CSV file
df = pd.read_csv('pairing_benchmarks.csv')

# Filter data for each implementation and sort by pairing_size
# We focus only on full pairing and miller loop as requested
full = df[df['implementation'] == 'full'].sort_values('pairing_size')
miller = df[df['implementation'] == 'miller'].sort_values('pairing_size')

# Create a figure with a decent size
fig, ax = plt.subplots(figsize=(10, 6))

# Define a dash pattern for the full implementation (1 point on, 3 points off)
dash_pattern = (0, (1, 3))

# Plot each series with custom styles, thicker lines, and markers
ax.plot(full['pairing_size'], full['mean_ms'], 
        label='Individual Pairings', color='blue', linestyle=dash_pattern, marker='o', linewidth=2)
ax.plot(miller['pairing_size'], miller['mean_ms'], 
        label='Multi-Miller Loop', color='green', linestyle='solid', marker='o', linewidth=2)

# Set only x-axis to logarithmic scale, keep y-axis linear
ax.set_xscale('log')
# ax.set_yscale('log')  # Removed to show direct ms values

# Custom ticks based on unique pairing sizes
pairing_sizes = sorted(df['pairing_size'].unique())
ax.set_xticks(pairing_sizes)
ax.set_xticklabels(pairing_sizes)

# Format y-axis to show milliseconds with appropriate precision
from matplotlib.ticker import FormatStrFormatter
ax.yaxis.set_major_formatter(FormatStrFormatter('%.1f'))

# Add text labels with the exact ms value next to each point
for i, row in full.iterrows():
    ax.annotate(f"{row['mean_ms']:.1f} ms", 
                (row['pairing_size'], row['mean_ms']),
                textcoords="offset points", 
                xytext=(0,10), 
                ha='center', 
                fontsize=8)

for i, row in miller.iterrows():
    ax.annotate(f"{row['mean_ms']:.1f} ms", 
                (row['pairing_size'], row['mean_ms']),
                textcoords="offset points", 
                xytext=(0,-15), 
                ha='center', 
                fontsize=8)

# Label axes and add a title
ax.set_xlabel('Number of Pairings')
ax.set_ylabel('Time (ms)')
ax.set_title('Pairing Performance: Individual vs. Multi-Miller Loop')

# Customize the legend: move it outside, increase font size, shorten line samples
ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0., fontsize=12, handlelength=1.5)

# Add a grid for readability
ax.grid(True, which='both', linestyle='--', linewidth=0.5)

# Adjust y-axis limits to leave room for annotations
y_max = max(full['mean_ms'].max(), miller['mean_ms'].max())
ax.set_ylim(0, y_max * 1.2)  # Add 20% padding at the top

# Adjust layout to accommodate the legend
plt.tight_layout()

# Create a second plot for speedup
fig2, ax2 = plt.subplots(figsize=(10, 6))

# Calculate speedup directly (making sure values exist for both implementations)
common_sizes = set(full['pairing_size'].values) & set(miller['pairing_size'].values)
speedup_data = []

for size in common_sizes:
    full_time = full[full['pairing_size'] == size]['mean_ms'].values[0]
    miller_time = miller[miller['pairing_size'] == size]['mean_ms'].values[0]
    speedup_data.append({'pairing_size': size, 'speedup': full_time / miller_time})

speedup_df = pd.DataFrame(speedup_data).sort_values('pairing_size')

# Plot speedup
ax2.plot(speedup_df['pairing_size'], speedup_df['speedup'], 
         color='red', marker='s', linestyle='-', linewidth=2)

# Add text labels with the exact speedup value next to each point
for i, row in speedup_df.iterrows():
    ax2.annotate(f"{row['speedup']:.1f}x", 
                (row['pairing_size'], row['speedup']),
                textcoords="offset points", 
                xytext=(0,10), 
                ha='center', 
                fontsize=9)

# Set logarithmic x-axis
ax2.set_xscale('log')
ax2.set_xticks(pairing_sizes)
ax2.set_xticklabels(pairing_sizes)

# Label axes and add a title
ax2.set_xlabel('Number of Pairings')
ax2.set_ylabel('Speedup Factor')
ax2.set_title('Performance Gain: Multi-Miller Loop vs. Individual Pairings')

# Add a grid for readability
ax2.grid(True, which='both', linestyle='--', linewidth=0.5)

# Add a horizontal line at y=1 for reference
ax2.axhline(y=1, color='gray', linestyle='--', alpha=0.7)

# Tight layout
plt.tight_layout()

# Save both plots
plt.figure(1)
plt.savefig('pairing_benchmark_comparison.png', dpi=300, bbox_inches='tight')

plt.figure(2)
plt.savefig('pairing_speedup_factor.png', dpi=300, bbox_inches='tight')

# Display the plots
plt.show()