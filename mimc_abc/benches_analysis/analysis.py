# import pandas as pd
# import matplotlib.pyplot as plt
# import seaborn as sns
# import numpy as np

# # Load the extracted data
# df = pd.read_csv('extracts/extract.csv')

# # Create a directory for outputs
# output_dir = 'extracts/plots'
# import os
# os.makedirs(output_dir, exist_ok=True)

# # Set style
# sns.set(style="whitegrid")
# plt.rcParams.update({'font.size': 12})

# # Define colors for implementations
# colors = {
#     'non_private_non_batch': 'blue',
#     'non_private_with_batch': 'green',
#     'multi_issuer_identity_binding': 'red',
#     'multi_credential_batch_verify': 'purple'
# }

# # Rename implementations for better readability
# implementation_names = {
#     'non_private_non_batch': 'Individual Verification',
#     'non_private_with_batch': 'Batch Verification',
#     'multi_issuer_identity_binding': 'Multi-Issuer Identity Binding',
#     'multi_credential_batch_verify': 'Multi-Credential Batch'
# }

# df['implementation_name'] = df['implementation'].map(implementation_names)

# # 1. Line graphs by credential count
# for cred_count in sorted(df['credential_count'].unique()):
#     plt.figure(figsize=(10, 6))
    
#     # Filter data for this credential count
#     cred_df = df[df['credential_count'] == cred_count]
    
#     # Create line plot
#     for impl in df['implementation'].unique():
#         impl_df = cred_df[cred_df['implementation'] == impl]
#         if not impl_df.empty:
#             plt.plot(
#                 impl_df['attribute_count'], 
#                 impl_df['mean_ms'], 
#                 marker='o', 
#                 linewidth=2, 
#                 label=implementation_names[impl],
#                 color=colors[impl]
#             )
    
#     plt.title(f'Execution Time for {cred_count} Credentials')
#     plt.xlabel('Attribute Count')
#     plt.ylabel('Execution Time (ms)')
#     plt.xticks(sorted(df['attribute_count'].unique()))
#     plt.legend()
#     plt.grid(True)
#     plt.tight_layout()
    
#     # Save figure
#     plt.savefig(f'{output_dir}/line_plot_creds_{cred_count}.png', dpi=300)
#     plt.close()

# # 2. Create a summary table
# pivot_table = df.pivot_table(
#     index=['credential_count', 'attribute_count'],
#     columns='implementation_name',
#     values='mean_ms'
# )

# # Save to CSV
# pivot_table.to_csv(f'{output_dir}/summary_table.csv')

# # 3. Calculate and create speedup table
# speedup_df = df.copy()

# # Create pivot with baseline values
# baseline_df = df[df['implementation'] == 'non_private_non_batch'].copy()
# baseline_pivot = baseline_df.pivot_table(
#     index=['credential_count', 'attribute_count'],
#     values='mean_ms'
# )

# # For each row in the dataframe, calculate speedup
# for idx, row in speedup_df.iterrows():
#     creds = row['credential_count']
#     attrs = row['attribute_count']
#     baseline_value = baseline_pivot.loc[(creds, attrs)].values[0]
#     speedup_df.loc[idx, 'speedup'] = baseline_value / row['mean_ms']

# # Create speedup pivot table
# speedup_pivot = speedup_df.pivot_table(
#     index=['credential_count', 'attribute_count'],
#     columns='implementation_name',
#     values='speedup'
# )

# # Save to CSV
# speedup_pivot.to_csv(f'{output_dir}/speedup_table.csv')

# # 4. Create bar charts for each attribute/credential combination
# for cred_count in sorted(df['credential_count'].unique()):
#     plt.figure(figsize=(12, 7))
    
#     # Filter data for this credential count
#     cred_df = df[df['credential_count'] == cred_count]
    
#     # Set up positions for grouped bars
#     attr_counts = sorted(cred_df['attribute_count'].unique())
#     impl_names = df['implementation_name'].unique()
    
#     x = np.arange(len(attr_counts))
#     width = 0.2  # Width of bars
    
#     # Create grouped bars
#     for i, impl in enumerate(df['implementation'].unique()):
#         impl_df = cred_df[cred_df['implementation'] == impl]
#         if not impl_df.empty:
#             values = []
#             for attr in attr_counts:
#                 val = impl_df[impl_df['attribute_count'] == attr]['mean_ms'].values
#                 values.append(val[0] if len(val) > 0 else 0)
                
#             plt.bar(
#                 x + (i - 1.5) * width, 
#                 values, 
#                 width=width, 
#                 label=implementation_names[impl],
#                 color=colors[impl]
#             )
    
#     plt.title(f'Execution Time Comparison for {cred_count} Credentials')
#     plt.xlabel('Attribute Count')
#     plt.ylabel('Execution Time (ms)')
#     plt.xticks(x, attr_counts)
#     plt.legend()
#     plt.grid(True, axis='y')
#     plt.tight_layout()
    
#     # Save figure
#     plt.savefig(f'{output_dir}/bar_plot_creds_{cred_count}.png', dpi=300)
#     plt.close()

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
    'multi_issuer_identity_binding': 'Private, Multi Issuer',
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
    
    plt.title(f'Verification Time vs. Credential Count ({attr_count} Attributes)')
    plt.xlabel('Number of Credentials')
    plt.ylabel('Execution Time (ms)')
    plt.xticks(sorted(df['credential_count'].unique()))
    plt.legend(loc='best')
    plt.grid(True, alpha=0.3)
    
    # Add a note about line styles
    plt.figtext(0.5, 0.01, "Dotted lines = Non-private, Solid lines = Private", 
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