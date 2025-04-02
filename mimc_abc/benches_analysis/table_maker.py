import pandas as pd
import numpy as np

# Load CSV data
df = pd.read_csv('extracts/extract.csv')

# Define the implementation mappings
implementations = {
    'verify': {
        'non_private_batch': 'non_private_with_batch',
        'non_private_multi': 'non_private_non_batch',
        'private_batch': 'multi_credential_batch_verify',
        'private_multi': 'multi_issuer_identity_binding_verify'
    },
    'show': {
        'private_batch': 'multi_credential_batch_show',
        'private_multi': 'multi_issuer_identity_binding_show'
    }
}

# Function to get value for a specific implementation, credential count and attribute count
def get_value(implementation, cred_count, attr_count):
    if implementation is None:
        return np.nan
        
    result = df[(df['implementation'] == implementation) & 
                (df['credential_count'] == cred_count) & 
                (df['attribute_count'] == attr_count)]
    if len(result) > 0:
        return result['mean_ms'].values[0]
    else:
        return np.nan

# Generate restructured LaTeX table
def generate_restructured_table():
    # Table header
    latex = "\\begin{table}[ht]\n"
    latex += "\\centering\n"
    latex += "\\caption{Performance of Anonymous Credential Operations (time in ms), using 16 attributes per credential}\n"
    latex += "\\label{tab:performance}\n"
    # latex += "\\begin{tabular}{lrrr}\n"
    latex += "\\begin{tabular}{l@{\\hspace{1.5em}}r@{\\hspace{1.5em}}r@{\\hspace{1.5em}}r}\n"
    latex += "\\toprule\n"
    
    # Fixed attribute count for clarity
    attr_count = 16  # Using 16 attributes as the representative case
    
    # Credential counts to include
    cred_counts = [4, 16, 32]
    
    # Section 1: Non-Private Verify Baseline
    latex += f"\\multicolumn{{4}}{{c}}{{\\textbf{{Signature Verify Baseline}}}} \\\\\n"
    latex += "\\midrule\n"
    latex += "Credential Count & 4 & 16 & 32 \\\\\n"
    latex += "\\midrule\n"
    
    # Single Issuer (batch) row
    row = ["Single Issuer"]
    for cred_count in cred_counts:
        implementation = implementations['verify']['non_private_batch']
        value = get_value(implementation, cred_count, attr_count)
        row.append(f"{value:.2f}")
    latex += " & ".join(row) + " \\\\\n"
    
    # Multi Issuer row
    row = ["Multi Issuer"]
    for cred_count in cred_counts:
        implementation = implementations['verify']['non_private_multi']
        value = get_value(implementation, cred_count, attr_count)
        row.append(f"{value:.2f}")
    latex += " & ".join(row) + " \\\\\n"
    
    # Section 2: Private Verify
    latex += "\\midrule\n"
    latex += f"\\multicolumn{{4}}{{c}}{{\\textbf{{Identity Binding Verify}}}} \\\\\n"
    latex += "\\midrule\n"
    latex += "Credential Count & 4 & 16 & 32 \\\\\n"
    latex += "\\midrule\n"
    
    # Single Issuer (batch) row
    row = ["Single Issuer"]
    for cred_count in cred_counts:
        implementation = implementations['verify']['private_batch']
        value = get_value(implementation, cred_count, attr_count)
        row.append(f"{value:.2f}")
    latex += " & ".join(row) + " \\\\\n"
    
    # Multi Issuer row
    row = ["Multi Issuer"]
    for cred_count in cred_counts:
        implementation = implementations['verify']['private_multi']
        value = get_value(implementation, cred_count, attr_count)
        row.append(f"{value:.2f}")
    latex += " & ".join(row) + " \\\\\n"
    
    # Section 3: Private Show + Verify
    latex += "\\midrule\n"
    latex += f"\\multicolumn{{4}}{{c}}{{\\textbf{{Identity Binding Show + Verify}}}} \\\\\n"
    latex += "\\midrule\n"
    latex += "Credential Count & 4 & 16 & 32 \\\\\n"
    latex += "\\midrule\n"
    
    # Single Issuer (batch) row
    row = ["Single Issuer"]
    for cred_count in cred_counts:
        show_impl = implementations['show']['private_batch']
        verify_impl = implementations['verify']['private_batch']
        
        show_value = get_value(show_impl, cred_count, attr_count)
        verify_value = get_value(verify_impl, cred_count, attr_count)
        total_value = show_value + verify_value
        
        row.append(f"{total_value:.2f}")
    latex += " & ".join(row) + " \\\\\n"
    
    # Multi Issuer row
    row = ["Multi Issuer"]
    for cred_count in cred_counts:
        show_impl = implementations['show']['private_multi']
        verify_impl = implementations['verify']['private_multi']
        
        show_value = get_value(show_impl, cred_count, attr_count)
        verify_value = get_value(verify_impl, cred_count, attr_count)
        total_value = show_value + verify_value
        
        row.append(f"{total_value:.2f}")
    latex += " & ".join(row) + " \\\\\n"
    
    # Table footer
    latex += "\\bottomrule\n"
    latex += "\\end{tabular}\n"
    latex += "\\end{table}\n"
    
    return latex

# Generate and print the LaTeX tables
restructured_table = generate_restructured_table()

print("Restructured Table:")
print(restructured_table)

# Save to files
with open('credential_performance_restructured.tex', 'w') as f:
    f.write(restructured_table)