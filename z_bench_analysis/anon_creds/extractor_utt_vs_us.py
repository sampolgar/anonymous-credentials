# import matplotlib.pyplot as plt

# # Data
# attribute_counts = [2, 5, 10, 15, 20, 30]
# g1_show = [1.14, 1.16, 1.22, 1.40, 1.41, 1.37]
# g2_show = [1.29, 1.29, 1.33, 1.37, 1.51, 1.59]
# g1_verify = [2.47, 2.73, 3.16, 3.47, 3.84, 4.67]
# g2_verify = [1.79, 2.01, 2.44, 2.72, 3.21, 3.79]
# g1_total = [3.61, 3.90, 4.38, 4.87, 5.25, 6.04]
# g2_total = [3.08, 3.30, 3.77, 4.09, 4.72, 5.37]

# # Compute percentage improvements
# show_imp = [(g1 - g2) / g1 * 100 for g1, g2 in zip(g1_show, g2_show)]
# verify_imp = [(g1 - g2) / g1 * 100 for g1, g2 in zip(g1_verify, g2_verify)]
# total_imp = [(g1 - g2) / g1 * 100 for g1, g2 in zip(g1_total, g2_total)]

# # Color scheme
# colors = {
#     "UTT": "#E45932",         # Dark Navy Blue
#     "Our Construction": "#50C878"  # Orange-Red
# }

# def annotate(ax, xs, ys1, ys2, imps):
#     """Add percentage improvement annotations between the two lines"""
#     for i, (x, y1, y2, imp) in enumerate(zip(xs, ys1, ys2, imps)):
#         # Position annotation halfway between the two lines
#         y_pos = min(y1, y2) - 0.15  # Adjust this value for better positioning
        
#         if imp >= 0:
#             text = f'{imp:.1f}% Faster'
#         else:
#             text = f'{abs(imp):.1f}% Slower'
            
#         # Only annotate every second point to avoid clutter
#         if i % 2 == 0:
#             ax.annotate(text, (x, y_pos), textcoords="offset points", 
#                         xytext=(0, -20), ha='center', fontsize=10, 
#                         bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.7))

# # Generate separate figures for each operation
# operations = {
#     "Show": (g1_show, g2_show, show_imp),
#     "Verify": (g1_verify, g2_verify, verify_imp),
#     "Show + Verify": (g1_total, g2_total, total_imp)
# }

# for op_name, (g1_data, g2_data, imp_data) in operations.items():
#     plt.figure(figsize=(8, 5))  # Larger figure size for better readability
    
#     # Plot with thicker lines and larger markers
#     plt.plot(attribute_counts, g1_data, marker='o', label='UTT', 
#              color=colors["UTT"], linewidth=2.5, markersize=8)
#     plt.plot(attribute_counts, g2_data, marker='o', label='Our Construction', 
#              color=colors["Our Construction"], linewidth=2.5, markersize=8)
    
#     # Add annotations if needed (uncomment to enable)
#     if op_name != "Show Operation":  # Skip annotations for Show Operation as per original code
#         annotate(plt.gca(), attribute_counts, g1_data, g2_data, imp_data)
    
#     plt.title(op_name, fontsize=16)
#     plt.xlabel('Number of Attributes', fontsize=14)
#     plt.ylabel('Time (ms)', fontsize=14)
#     plt.legend(fontsize=12, loc='best')
#     plt.grid(True, alpha=0.3)
#     plt.xticks(attribute_counts, fontsize=12)
#     plt.yticks(fontsize=12)
    
#     # Add some padding to y-axis for annotations
#     y_min, y_max = plt.ylim()
#     plt.ylim(y_min - 0.5, y_max * 1.1)
    
#     plt.tight_layout()
#     plt.show()


    

import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import numpy as np

# Set global font to be bold
# plt.rcParams['font.weight'] = 'bold'
plt.rcParams['axes.labelweight'] = 'bold'
plt.rcParams['axes.titleweight'] = 'bold'
plt.rcParams['font.size'] = 12
# plt.rcParams['figure.titleweight'] = 'bold'

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

# Color scheme - more vibrant and distinguishable colors
colors = {
    "UTT": "#E74C3C",         # Brighter red
    "Our Construction": "#2ECC71"  # Brighter green
}

def annotate(ax, xs, ys1, ys2, imps, index_to_show=None):
    """Add percentage improvement annotations between the two lines"""
    for i, (x, y1, y2, imp) in enumerate(zip(xs, ys1, ys2, imps)):
        # Skip if not in index_to_show (if provided)
        if index_to_show is not None and i not in index_to_show:
            continue
            
        # Position annotation halfway between the two lines
        if y1 > y2:  # "Our Construction" is faster (lower time)
            y_pos = y2 + (y1 - y2) * 0.5
            text = f'{imp:.1f}% Faster'
        else:
            y_pos = y1 + (y2 - y1) * 0.5
            text = f'{abs(imp):.1f}% Slower'
            
        # Add annotation with improved visibility
        ax.annotate(text, (x, y_pos), 
                   textcoords="offset points", 
                   xytext=(0, 0), 
                   ha='center', 
                   va='center',
                   fontsize=10, 
                   fontweight='bold',
                   bbox=dict(boxstyle="round,pad=0.3", 
                            fc="white", 
                            ec="gray", 
                            alpha=0.9,
                            linewidth=1.5))

# Create a unified figure with 3 subplots
fig = plt.figure(figsize=(14, 10))
gs = fig.add_gridspec(2, 2, height_ratios=[1.2, 1])

# Top plot (Show + Verify) spans both columns
ax_total = fig.add_subplot(gs[0, :])
ax_show = fig.add_subplot(gs[1, 0])
ax_verify = fig.add_subplot(gs[1, 1])

# Common styling function
def style_plot(ax, title, g1_data, g2_data, y_min=None, y_max=None, label_size=14):
    ax.plot(attribute_counts, g1_data, marker='o', label='UTT', 
            color=colors["UTT"], linewidth=2.5, markersize=8)
    ax.plot(attribute_counts, g2_data, marker='o', label='Our Construction', 
            color=colors["Our Construction"], linewidth=2.5, markersize=8)
    
    ax.set_title(title, fontsize=16, pad=10, fontweight='bold')
    ax.set_xlabel('Attributes', fontsize=label_size)
    ax.set_ylabel('Time (ms)', fontsize=label_size)
    ax.legend(fontsize=12, loc='best')
    ax.grid(True, alpha=0.3)
    ax.set_xticks(attribute_counts)
    ax.set_xticklabels(attribute_counts, fontsize=12, fontweight='bold')
    ax.tick_params(axis='y', labelsize=12)
    
    # Make y-tick labels bold 
    for label in ax.get_yticklabels():
        label.set_fontweight('bold')
    
    # Add border to make graphs stand out
    for spine in ax.spines.values():
        spine.set_linewidth(1.5)
        
    if y_min is not None and y_max is not None:
        ax.set_ylim(y_min, y_max)

# Style each plot
style_plot(ax_total, "Show + Verify", g1_total, g2_total, 2.5, 6.5)
style_plot(ax_show, "Show", g1_show, g2_show, 0.8, 1.7, label_size=14)
style_plot(ax_verify, "Verify", g1_verify, g2_verify, 1.5, 5.0, label_size=14)

# Add annotations - use specific indices to avoid overcrowding
annotate(ax_total, attribute_counts, g1_total, g2_total, total_imp, [0, 2, 4])
annotate(ax_show, attribute_counts, g1_show, g2_show, show_imp, [0, 3, 5])
annotate(ax_verify, attribute_counts, g1_verify, g2_verify, verify_imp, [0, 3, 5])

# Add a main title
# fig.suptitle("My Construction is the fastest for Credential Presentation (Show + Verify)", 
#             fontsize=20,  y=0.98)

# # Add a subtitle explanation
# plt.figtext(0.5, 0.92, "We improve key operations: Verify and Show + Verify", 
#            ha='center', fontsize=16)

# Adjust layout
# plt.tight_layout(rect=[0, 0, 1, 0.92])
# plt.subplots_adjust(top=0.88, hspace=0.3, wspace=0.2)

# Save the figure in high resolution
plt.savefig('performance_comparison_improved.pdf', dpi=300, bbox_inches='tight')
plt.savefig('performance_comparison_improved.png', dpi=300, bbox_inches='tight')

# Show the figure
plt.show()