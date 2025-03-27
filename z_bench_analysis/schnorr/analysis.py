import pandas as pd
import matplotlib.pyplot as plt

# Load your data (replace 'benchmark_results.csv' with your file path)
df = pd.read_csv('schnorr_benchmarks.csv')

# Filter data for each series
commitment_msm = df[(df['operation'] == 'commitment') & (df['implementation'] == 'msm')].sort_values('message_size')
commitment_naive = df[(df['operation'] == 'commitment') & (df['implementation'] == 'naive')].sort_values('message_size')
verification_msm = df[(df['operation'] == 'verification') & (df['implementation'] == 'msm')].sort_values('message_size')
verification_naive = df[(df['operation'] == 'verification') & (df['implementation'] == 'naive')].sort_values('message_size')

# Create a figure with a decent size
fig, ax = plt.subplots(figsize=(10, 6))

# Define a shorter dash pattern (2 points on, 2 points off)
dash_pattern = (0, (1, 3))

# Plot each series with thicker lines and custom styles
ax.plot(commitment_msm['message_size'], commitment_msm['mean_ms'], 
        label='Commitment MSM', color='blue', linestyle='solid', marker='o', linewidth=2)
ax.plot(commitment_naive['message_size'], commitment_naive['mean_ms'], 
        label='Commitment Naive', color='blue', linestyle=dash_pattern, marker='o', linewidth=2)
ax.plot(verification_msm['message_size'], verification_msm['mean_ms'], 
        label='Verification MSM', color='red', linestyle='solid', marker='o', linewidth=2)
ax.plot(verification_naive['message_size'], verification_naive['mean_ms'], 
        label='Verification Naive', color='red', linestyle=dash_pattern, marker='o', linewidth=2)

# Set logarithmic x-axis and custom ticks
ax.set_xscale('log')
message_sizes = sorted(df['message_size'].unique())
ax.set_xticks(message_sizes)
ax.set_xticklabels(message_sizes)

# Label axes and add title
ax.set_xlabel('Message Size')
ax.set_ylabel('Time (ms)')
ax.set_title('Schnorr Protocol: Commitment and Verification Times')

# Improve the legend: move it outside, increase font size, shorten line samples
ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0., fontsize=12, handlelength=1.5)

# Add a grid for readability
ax.grid(True, which='both', linestyle='--', linewidth=0.5)

# Adjust layout to fit the legend
plt.tight_layout()

# Show the plot
plt.show()

# Optional: Save to file
plt.savefig('schnorr_benchmark_improved.png', dpi=300, bbox_inches='tight')