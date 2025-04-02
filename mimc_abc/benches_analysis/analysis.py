# import pandas as pd
# import matplotlib.pyplot as plt
# import seaborn as sns
# import numpy as np
# import os

# # Create a directory for outputs
# output_dir = 'plots'
# os.makedirs(output_dir, exist_ok=True)

# # Set style for academic visualization
# sns.set_style("whitegrid")
# plt.rcParams.update({
#     'font.size': 12,
#     'font.family': 'serif',
#     'figure.figsize': (10, 6)
# })

# # Load the data
# df = pd.read_csv('extracts/extract.csv')

# # Map implementations to new categories with better descriptions
# implementation_mapping = {
#     'non_private_with_batch': 'Non-Private, Single Issuer (Batch Verif)',
#     'non_private_non_batch': 'Non-Private, Multi Issuer',
#     'multi_issuer_identity_binding': 'Private, Multi Issuer',
#     'multi_issuer_identity_binding_show': 'Private, Multi Issuer Show',
#     'multi_issuer_identity_binding_verify': 'Private, Multi Issuer Verify',
#     'multi_credential_batch_show': 'Private, Single Issuer Show',
#     'multi_credential_batch_verify': 'Private, Single Issuer (Batch Verif)'
# }

# # Define visualization properties (colors and line styles)
# style_props = {
#     'Non-Private, Single Issuer (Batch Verif)': {'color': 'darkgreen', 'linestyle': 'solid', 'marker': 's'},
#     'Non-Private, Multi Issuer': {'color': 'blue', 'linestyle': 'solid', 'marker': 'o'},
#     'Private, Single Issuer (Batch Verif)': {'color': 'darkgreen', 'linestyle': 'dotted', 'marker': 's'},
#     'Private, Multi Issuer': {'color': 'purple', 'linestyle': 'dotted', 'marker': 'o'},
#     'Private, Single Issuer Show': {'color': 'red', 'linestyle': 'dashed', 'marker': '^'},
#     'Private, Multi Issuer Show': {'color': 'orange', 'linestyle': 'dashed', 'marker': 'v'},
#     'Private, Multi Issuer Verify': {'color': 'brown', 'linestyle': 'dashdot', 'marker': 'D'}
# }

# # Apply the mapping
# df['implementation_name'] = df['implementation'].map(implementation_mapping)

# # 1. Create line graphs by attribute count (with credentials on x-axis)
# for attr_count in sorted(df['attribute_count'].unique()):
#     plt.figure(figsize=(10, 6))
    
#     # Filter data for this attribute count
#     attr_df = df[df['attribute_count'] == attr_count]
    
#     # Create line plot
#     for impl in sorted(attr_df['implementation'].unique()):
#         impl_name = implementation_mapping[impl]
#         impl_df = attr_df[attr_df['implementation'] == impl]
        
#         # Sort by credential count
#         impl_df = impl_df.sort_values('credential_count')
        
#         # Plot with specified style
#         props = style_props[impl_name]
#         plt.plot(
#             impl_df['credential_count'], 
#             impl_df['mean_ms'], 
#             marker=props['marker'],
#             linestyle=props['linestyle'],
#             color=props['color'],
#             linewidth=2,
#             markersize=8,
#             label=impl_name
#         )
    
#     plt.title(f'Verification Time vs. Credential Count ({attr_count} Attributes per Credential)')
#     plt.xlabel('Number of Credentials')
#     plt.ylabel('Execution Time (ms)')
#     plt.xticks(sorted(df['credential_count'].unique()))
#     plt.legend(loc='best')
#     plt.grid(True, alpha=0.3)
    
#     # Add a note about line styles
#     plt.figtext(0.5, 0.01, "Different line styles represent different implementation types", 
#                 ha="center", fontsize=10, style='italic')
    
#     plt.tight_layout()
    
#     # Save figure
#     plt.savefig(f'{output_dir}/line_plot_attrs_{attr_count}.png', dpi=300)
#     plt.close()

# # 2. Create a summary table
# pivot_table = df.pivot_table(
#     index=['attribute_count', 'credential_count'],
#     columns='implementation_name',
#     values='mean_ms'
# )

# # Save to CSV
# pivot_table.to_csv(f'{output_dir}/summary_table.csv')

# # 3. Create separate comparisons for show vs verify operations
# plt.figure(figsize=(12, 8))

# # Filter for show and verify operations
# show_df = df[df['implementation'].str.contains('show')]
# verify_df = df[df['implementation'].str.contains('verify') | 
#                (df['implementation'].isin(['non_private_with_batch', 'non_private_non_batch', 'multi_issuer_identity_binding']))]

# # Plot show operations
# plt.subplot(1, 2, 1)
# for impl in sorted(show_df['implementation'].unique()):
#     impl_name = implementation_mapping[impl]
#     impl_df = show_df[show_df['implementation'] == impl]
    
#     # Filter for a specific attribute count for clarity (e.g., 16)
#     impl_df = impl_df[impl_df['attribute_count'] == 16]
#     impl_df = impl_df.sort_values('credential_count')
    
#     props = style_props[impl_name]
#     plt.plot(
#         impl_df['credential_count'],
#         impl_df['mean_ms'],
#         marker=props['marker'],
#         linestyle=props['linestyle'],
#         color=props['color'],
#         label=impl_name
#     )

# plt.title('Show Operation Performance (16 Attributes)')
# plt.xlabel('Number of Credentials')
# plt.ylabel('Execution Time (ms)')
# plt.xticks(sorted(df['credential_count'].unique()))
# plt.legend()
# plt.grid(True, alpha=0.3)

# # Plot verify operations
# plt.subplot(1, 2, 2)
# for impl in sorted(verify_df['implementation'].unique()):
#     impl_name = implementation_mapping[impl]
#     impl_df = verify_df[verify_df['implementation'] == impl]
    
#     # Filter for a specific attribute count for clarity (e.g., 16)
#     impl_df = impl_df[impl_df['attribute_count'] == 16]
#     impl_df = impl_df.sort_values('credential_count')
    
#     props = style_props[impl_name]
#     plt.plot(
#         impl_df['credential_count'],
#         impl_df['mean_ms'],
#         marker=props['marker'],
#         linestyle=props['linestyle'],
#         color=props['color'],
#         label=impl_name
#     )

# plt.title('Verify Operation Performance (16 Attributes)')
# plt.xlabel('Number of Credentials')
# plt.ylabel('Execution Time (ms)')
# plt.xticks(sorted(df['credential_count'].unique()))
# plt.legend()
# plt.grid(True, alpha=0.3)

# plt.tight_layout()
# plt.savefig(f'{output_dir}/show_vs_verify_comparison.png', dpi=300)
# plt.close()

# # 4. Create bar chart comparing operations by implementation type
# plt.figure(figsize=(14, 8))

# # We'll use fixed values for this comparison (16 credentials, 16 attributes)
# comparison_df = df[(df['credential_count'] == 16) & (df['attribute_count'] == 16)]

# # Group implementations by type
# impl_categories = {
#     'Non-Private': ['non_private_with_batch', 'non_private_non_batch'],
#     'Private (Single Issuer)': ['multi_credential_batch_show', 'multi_credential_batch_verify'],
#     'Private (Multi Issuer)': ['multi_issuer_identity_binding', 'multi_issuer_identity_binding_show', 'multi_issuer_identity_binding_verify']
# }

# # Define x positions for the bars
# bar_width = 0.2
# x_positions = np.arange(len(impl_categories))

# # Plot bars for different operations
# for i, impl in enumerate(sorted(comparison_df['implementation'].unique())):
#     values = []
#     for category in impl_categories.keys():
#         if impl in impl_categories[category]:
#             val = comparison_df[comparison_df['implementation'] == impl]['mean_ms'].values[0]
#             values.append(val)
#         else:
#             values.append(0)  # No bar for this category
    
#     # Only plot non-zero values
#     non_zero_indices = [idx for idx, val in enumerate(values) if val > 0]
#     non_zero_values = [values[idx] for idx in non_zero_indices]
#     non_zero_positions = [x_positions[idx] + (i * bar_width - 0.3) for idx in non_zero_indices]
    
#     if non_zero_values:
#         plt.bar(
#             non_zero_positions,
#             non_zero_values,
#             width=bar_width,
#             label=implementation_mapping[impl]
#         )

# plt.title('Performance Comparison (16 Credentials, 16 Attributes)')
# plt.xlabel('Implementation Category')
# plt.ylabel('Execution Time (ms)')
# plt.xticks(x_positions, impl_categories.keys())
# plt.legend(loc='upper left')
# plt.grid(True, alpha=0.3, axis='y')

# plt.tight_layout()
# plt.savefig(f'{output_dir}/implementation_comparison.png', dpi=300)
# plt.close()

# print(f"Analysis complete. Results saved to {output_dir}/")

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# Load the extracted data
df = pd.read_csv('extracts/extract.csv')


# Create a directory for outputs
output_dir = 'plots'
import os
os.makedirs(output_dir, exist_ok=True)

# Set style for academic visualization
sns.set_style("whitegrid")
plt.rcParams.update({
    'font.size': 12,
    'font.family': 'serif',
    'figure.figsize': (10, 6)
})

# Map implementations to new categories with better descriptions
implementation_mapping = {
    'non_private_with_batch': 'Non-Private, Single Issuer (Batch Verif)',
    'non_private_non_batch': 'Non-Private, Multi Issuer',
    'multi_issuer_identity_binding_show': 'Private, Multi Issuer Show',
    'multi_issuer_identity_binding_verify': 'Private, Multi Issuer Verify',
    'multi_credential_batch_show': 'Private, Single Issuer Show',
    'multi_credential_batch_verify': 'Private, Single Issuer (Batch Verif)'
}

# Define visualization properties (colors and line styles)
style_props = {
    'Non-Private, Single Issuer (Batch Verif)': {'color': 'darkgreen', 'linestyle': 'solid', 'marker': 's'},
    'Non-Private, Multi Issuer': {'color': 'blue', 'linestyle': 'solid', 'marker': 'o'},
    'Private, Single Issuer (Batch Verif)': {'color': 'darkgreen', 'linestyle': 'dotted', 'marker': 's'},
    'Private, Multi Issuer': {'color': 'blue', 'linestyle': 'dotted', 'marker': 'o'},
}

# Apply the mapping
df['implementation_name'] = df['implementation'].map(implementation_mapping)

# 1. Create line graphs by attribute count (with credentials on x-axis)
for attr_count in sorted(df['attribute_count'].unique()):
    plt.figure(figsize=(10, 6))
    
    # Filter data for this attribute count
    attr_df = df[df['attribute_count'] == attr_count]
    
    # Create line plot
    for impl_name in style_props.keys():
        if impl_name in attr_df['implementation_name'].values:
            impl_df = attr_df[attr_df['implementation_name'] == impl_name]
            
            # Sort by credential count
            impl_df = impl_df.sort_values('credential_count')
            
            # Plot with specified style
            props = style_props[impl_name]
            plt.plot(
                impl_df['credential_count'], 
                impl_df['mean_ms'], 
                marker=props['marker'],
                linestyle=props['linestyle'],
                color=props['color'],
                linewidth=2.5 if 'solid' in props['linestyle'] else 2,
                markersize=8,
                label=impl_name
            )
    
    plt.title(f'Verification Time vs. Credential Count ({attr_count} Attributes per Credential)')
    plt.xlabel('Number of Credentials')
    plt.ylabel('Execution Time (ms)')
    plt.xticks(sorted(df['credential_count'].unique()))
    plt.legend(loc='best')
    plt.grid(True, alpha=0.3)
    
    # Add a note about line styles
    plt.figtext(0.5, 0.01, "Solid lines = Non-Private, Dotted lines = Private", 
                ha="center", fontsize=10, style='italic')
    
    plt.tight_layout()
    
    # Save figure
    plt.savefig(f'{output_dir}/line_plot_attrs_{attr_count}.png', dpi=300)
    plt.close()

# 2. Create a summary table with the new implementation names
pivot_table = df.pivot_table(
    index=['attribute_count', 'credential_count'],
    columns='implementation_name',
    values='mean_ms'
)

# Save to CSV
pivot_table.to_csv(f'{output_dir}/summary_table.csv')

# 3. Create a comparison plot showing scaling trends for all implementations
plt.figure(figsize=(12, 8))

# For each implementation, create a subplot showing scaling with credential count
for i, impl in enumerate(df['implementation_name'].unique()):
    plt.subplot(2, 2, i+1)
    
    impl_df = df[df['implementation_name'] == impl]
    
    # Create lines for each attribute count
    for attr in sorted(impl_df['attribute_count'].unique()):
        attr_impl_df = impl_df[impl_df['attribute_count'] == attr]
        attr_impl_df = attr_impl_df.sort_values('credential_count')
        
        plt.plot(
            attr_impl_df['credential_count'],
            attr_impl_df['mean_ms'],
            marker='o',
            label=f'{attr} Attributes'
        )
    
    plt.title(impl)
    plt.xlabel('Number of Credentials')
    plt.ylabel('Execution Time (ms)')
    plt.xticks(sorted(df['credential_count'].unique()))
    plt.legend()
    plt.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig(f'{output_dir}/scaling_comparison.png', dpi=300)
plt.close()

print(f"Analysis complete. Results saved to {output_dir}/")