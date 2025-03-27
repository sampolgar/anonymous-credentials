#!/usr/bin/env python3
import os
import json
import pandas as pd
from pathlib import Path

# Define the base directory for Criterion benchmark results
BASE_DIR = Path("../../target/criterion/schnorr")

# Define the scheme name
SCHEME = "Schnorr"

def extract_operation_impl_size(operation_impl_dir, size_dir):
    """
    Extract operation, implementation, and size from directory names like 'commitment_msm', '4'
    Returns a tuple (operation, implementation, size)
    """
    try:
        # Parse the operation and implementation from the directory name
        if '_' in operation_impl_dir:
            parts = operation_impl_dir.split('_')
            if len(parts) == 2:
                operation, impl = parts
                # Handle 'verify_naive' etc.
                if operation == 'verify':
                    operation = 'verification'
                
                # Parse the size from the size directory
                size = int(size_dir)
                
                return operation, impl, size
        
        return None, None, None
            
    except Exception as e:
        print(f"Error parsing directory {operation_impl_dir}/{size_dir}: {e}")
        return None, None, None

def extract_mean_ms(json_file):
    """
    Extract the mean execution time in milliseconds from a Criterion JSON file.
    Assumes the mean is in nanoseconds under 'mean' > 'point_estimate'.
    """
    with open(json_file, 'r') as f:
        data = json.load(f)
    mean_ns = data['mean']['point_estimate']  # Mean time in nanoseconds
    mean_ms = mean_ns / 1_000_000  # Convert to milliseconds
    return mean_ms

def extract_benchmark_data(base_dir: Path, scheme: str):
    """
    Extract Schnorr benchmark data from Criterion directories and return a DataFrame.
    """
    all_data = []
    
    # Handle special cases like 'report' directory
    skip_dirs = ['report']
    
    # Walk through the base directory
    for operation_impl_dir in os.listdir(base_dir):
        # Skip the 'report' directory and any files
        if operation_impl_dir in skip_dirs or not os.path.isdir(base_dir / operation_impl_dir):
            continue
            
        # Look for size directories within each operation_impl directory
        op_impl_path = base_dir / operation_impl_dir
        for size_dir in os.listdir(op_impl_path):
            # Skip any non-integer directories
            try:
                int(size_dir)
            except ValueError:
                continue
                
            # Extract operation, implementation and size
            operation, impl, size = extract_operation_impl_size(operation_impl_dir, size_dir)
            if operation is None or impl is None or size is None:
                continue
                
            # Path to the report directory
            report_dir = op_impl_path / size_dir / "new"
            if report_dir.exists():
                # Look for JSON files in the report directory
                json_files = list(report_dir.glob("estimates.json"))
                if json_files:
                    print(f"Found JSON file for {operation}_{impl}/{size}")
                    json_file = json_files[0]  # Use the first JSON file found
                    mean_ms = extract_mean_ms(json_file)
                    all_data.append({
                        "scheme": scheme,
                        "operation": operation,
                        "implementation": impl,
                        "message_size": size,
                        "mean_ms": mean_ms
                    })
                else:
                    print(f"No JSON file found in {report_dir}")
    
    if not all_data:
        print("No benchmark data found in the specified directory!")
        return pd.DataFrame()
    
    # Create a DataFrame and sort it
    df = pd.DataFrame(all_data)
    df = df.sort_values(["operation", "implementation", "message_size"])
    return df

def calculate_speedup(df):
    """
    Calculate speedup ratios between naive and MSM implementations.
    Adds a 'speedup' column to the DataFrame.
    """
    # Create a copy of the DataFrame
    result_df = df.copy()
    result_df['speedup'] = None  # Initialize speedup column
    
    # Group by operation and message_size
    grouped = df.groupby(['operation', 'message_size'])
    
    # For each group, calculate speedup
    for (op, size), group in grouped:
        # Find naive and MSM implementations for this operation and size
        naive_row = group[group['implementation'] == 'naive']
        msm_row = group[group['implementation'] == 'msm']
        
        # Calculate speedup if both implementations exist
        if not naive_row.empty and not msm_row.empty:
            naive_time = naive_row.iloc[0]['mean_ms']
            msm_time = msm_row.iloc[0]['mean_ms']
            
            # Update the MSM row with the speedup value
            msm_idx = msm_row.index[0]
            result_df.at[msm_idx, 'speedup'] = naive_time / msm_time
    
    return result_df

def main():
    # Run the extraction
    print(f"Extracting benchmark data from {BASE_DIR}")
    benchmark_df = extract_benchmark_data(BASE_DIR, SCHEME)
    
    if benchmark_df.empty:
        print("No data found. Please ensure benchmarks have been run.")
        return
        
    # Calculate speedup ratios
    benchmark_df = calculate_speedup(benchmark_df)
    
    # Save to CSV
    output_file = "schnorr_benchmarks.csv"
    benchmark_df.to_csv(output_file, index=False)
    print(f"Benchmark data successfully saved to {output_file}")
    
    # Display summary statistics
    print("\nSummary of extracted data:")
    summary = benchmark_df.groupby(['operation', 'implementation']).agg({
        'mean_ms': ['min', 'max', 'mean'],
        'speedup': ['min', 'max', 'mean']
    }).reset_index()
    print(summary)
    
    # Print shape of the dataset
    print(f"\nDataset contains {benchmark_df.shape[0]} rows with {len(benchmark_df['operation'].unique())} operations, " 
          f"{len(benchmark_df['implementation'].unique())} implementations, and "
          f"{len(benchmark_df['message_size'].unique())} different message sizes.")

if __name__ == "__main__":
    main()

# Define the scheme name
SCHEME = "Schnorr"

# Define the operations to extract
OPERATIONS = ["commitment", "prove", "verification", "scaling"]

# Define the implementations to extract
IMPLEMENTATIONS = ["msm", "naive", "standard"]  # standard is for the proving operation

def extract_size_impl(dir_name):
    """
    Extract message size and implementation from a directory name like 'msm/4'
    Returns a tuple (size, implementation)
    """
    try:
        parts = dir_name.split('/')
        if len(parts) != 2:
            return None, None
            
        impl, size_str = parts
        size = int(size_str)
        
        return size, impl
    except Exception as e:
        print(f"Error parsing directory name {dir_name}: {e}")
        return None, None

def extract_mean_ms(json_file):
    """
    Extract the mean execution time in milliseconds from a Criterion JSON file.
    Assumes the mean is in nanoseconds under 'mean' > 'point_estimate'.
    """
    with open(json_file, 'r') as f:
        data = json.load(f)
    mean_ns = data['mean']['point_estimate']  # Mean time in nanoseconds
    mean_ms = mean_ns / 1_000_000  # Convert to milliseconds
    return mean_ms

def extract_benchmark_data(base_dir: Path, scheme: str, operations: list):
    """
    Extract Schnorr benchmark data from Criterion directories and return a DataFrame.
    """
    all_data = []
    
    # Walk through each operation directory
    for operation in operations:
        op_dir = base_dir / operation
        if not op_dir.exists():
            print(f"Operation directory not found: {op_dir}")
            continue
            
        # Find all implementation/size directories
        for impl_size_dir in op_dir.glob("*/*"):
            dir_name = str(impl_size_dir.relative_to(op_dir))
            
            # Extract size and implementation
            size, impl = extract_size_impl(dir_name)
            if size is None or impl is None:
                continue
                
            # Path to the report directory
            report_dir = impl_size_dir / "new"
            if report_dir.exists():
                # Look for JSON files in the report directory
                json_files = list(report_dir.glob("estimates.json"))
                if json_files:
                    print(f"Found JSON file for {operation}/{impl}/{size}")
                    json_file = json_files[0]  # Use the first JSON file found
                    mean_ms = extract_mean_ms(json_file)
                    all_data.append({
                        "scheme": scheme,
                        "operation": operation,
                        "implementation": impl,
                        "message_size": size,
                        "mean_ms": mean_ms
                    })
                else:
                    print(f"No JSON file found in {report_dir}")
    
    if not all_data:
        print("No benchmark data found in the specified directory!")
        return pd.DataFrame()
    
    # Create a DataFrame and sort it
    df = pd.DataFrame(all_data)
    df = df.sort_values(["operation", "implementation", "message_size"])
    return df

def calculate_speedup(df):
    """
    Calculate speedup ratios between naive and MSM implementations.
    Adds a 'speedup' column to the DataFrame.
    """
    # Create a copy of the DataFrame
    result_df = df.copy()
    
    # Group by operation and message_size
    grouped = df.groupby(['operation', 'message_size'])
    
    # For each group, calculate speedup
    for (op, size), group in grouped:
        # Find naive and MSM implementations for this operation and size
        naive_row = group[group['implementation'] == 'naive']
        msm_row = group[group['implementation'] == 'msm']
        
        # Calculate speedup if both implementations exist
        if not naive_row.empty and not msm_row.empty:
            naive_time = naive_row.iloc[0]['mean_ms']
            msm_time = msm_row.iloc[0]['mean_ms']
            
            # Update the MSM row with the speedup value
            msm_idx = msm_row.index[0]
            result_df.at[msm_idx, 'speedup'] = naive_time / msm_time
    
    return result_df

def main():
    # Run the extraction
    print(f"Extracting benchmark data from {BASE_DIR}")
    benchmark_df = extract_benchmark_data(BASE_DIR, SCHEME, OPERATIONS)
    
    if benchmark_df.empty:
        print("No data found. Please ensure benchmarks have been run.")
        return
        
    # Calculate speedup ratios
    benchmark_df = calculate_speedup(benchmark_df)
    
    # Save to CSV
    output_file = "schnorr_benchmarks.csv"
    benchmark_df.to_csv(output_file, index=False)
    print(f"Benchmark data successfully saved to {output_file}")
    
    # Display summary statistics
    print("\nSummary of extracted data:")
    summary = benchmark_df.groupby(['operation', 'implementation']).agg({
        'mean_ms': ['min', 'max', 'mean'],
        'speedup': ['min', 'max', 'mean']
    }).reset_index()
    print(summary)
    
    # Print shape of the dataset
    print(f"\nDataset contains {benchmark_df.shape[0]} rows with {len(benchmark_df['operation'].unique())} operations, " 
          f"{len(benchmark_df['implementation'].unique())} implementations, and "
          f"{len(benchmark_df['message_size'].unique())} different message sizes.")

if __name__ == "__main__":
    main()