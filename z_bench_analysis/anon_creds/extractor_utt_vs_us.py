import matplotlib.pyplot as plt

# Data
attribute_counts = [2, 5, 10, 15, 20, 30]
g1_show = [1.14, 1.16, 1.22, 1.40, 1.41, 1.37]
g2_show = [1.29, 1.29, 1.33, 1.37, 1.51, 1.59]
g1_verify = [2.47, 2.73, 3.16, 3.47, 3.84, 4.67]
g2_verify = [1.79, 2.01, 2.44, 2.72, 3.21, 3.79]
g1_total = [3.61, 3.90, 4.38, 4.87, 5.25, 6.04]
g2_total = [3.08, 3.30, 3.77, 4.09, 4.72, 5.37]

# Compute percentage improvements
show_imp = [(g1 - g2) / g1 * 100 for g1, g2 in zip(g1_show, g2_show)]
verify_imp = [(g1 - g2) / g1 * 100 for g1, g2 in zip(g1_verify, g2_verify)]
total_imp = [(g1 - g2) / g1 * 100 for g1, g2 in zip(g1_total, g2_total)]

def annotate(ax, xs, ys, imps):
    for x, y, imp in zip(xs, ys, imps):
        if imp >= 0:
            text = f'{imp:.1f}% Speedup'
        else:
            text = f'{abs(imp):.1f}% '
        ax.annotate(text, (x, y), textcoords="offset points", xytext=(0, 8), ha='center',  fontsize=8)

# Separate plots
# Show
fig = plt.figure(figsize=(8, 4))
ax = fig.add_subplot(111)
ax.plot(attribute_counts, g1_show, marker='o', label='UTT', color="#21305F")
ax.plot(attribute_counts, g2_show, marker='o', label='Our Construction', color="#E45932")
# annotate(ax, attribute_counts, g2_show, show_imp)
ax.set_title('Show Operation')
ax.set_xlabel('Number of Attributes')
ax.set_ylabel('Time (ms)')
ax.legend()
ax.grid(True)
plt.tight_layout()
plt.show()

# Verify
fig = plt.figure(figsize=(8, 4))
ax = fig.add_subplot(111)
ax.plot(attribute_counts, g1_verify, marker='o', label='UTT', color="#21305F")
ax.plot(attribute_counts, g2_verify, marker='o', label='Our Construction', color="#E45932")
annotate(ax, attribute_counts, g2_verify, verify_imp)
ax.set_title('Verify Operation')
ax.set_xlabel('Number of Attributes')
ax.set_ylabel('Time (ms)')
ax.legend()
ax.grid(True)
plt.tight_layout()
plt.show()

# Show + Verify
fig = plt.figure(figsize=(8, 4))
ax = fig.add_subplot(111)
ax.plot(attribute_counts, g1_total, marker='o', label='UTT', color="#21305F")
ax.plot(attribute_counts, g2_total, marker='o', label='Our Construction', color="#E45932")
annotate(ax, attribute_counts, g2_total, total_imp)
ax.set_title('Show + Verify Operation')
ax.set_xlabel('Number of Attributes')
ax.set_ylabel('Time (ms)')
ax.legend()
ax.grid(True)
plt.tight_layout()
plt.show()