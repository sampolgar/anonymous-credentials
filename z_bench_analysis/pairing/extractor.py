#!/usr/bin/env python3
import os
import json
import pandas as pd
from pathlib import Path

# Define the base directory for Criterion benchmark results
BASE_DIR = Path("../../target/criterion/pairing")

# Define the scheme name
SCHEME = "BLS12-381"

# Define the operation name
OPERATION = "pairing_product"

# Mapping from benchmark directory names to implementation names
IMPL_MAPPING = {
    "full_pairings": "full",
    "multi_miller": "miller",
}

def extract_mean_ms(json_file: Path) -> float:
    """
    Extract the mean execution time in milliseconds from a Criterion JSON file.
    Assumes the mean is in nanoseconds under 'mean' > 'point_estimate'.
    
    Args:
        json_file (Path): Path to the estimates.json file.
    Returns:
        float: Mean execution time in milliseconds.
    Raises:
        FileNotFoundError: If the JSON file is missing.
        KeyError: If the expected JSON structure is not found.
    """
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        mean_ns = data['mean']['point_estimate']  # Mean time in nanoseconds
        return mean_ns / 1_000_000  # Convert to milliseconds
    except (FileNotFoundError, KeyError) as e:
        print(f"Error processing {json_file}: {e}")
        return None

def extract_benchmark_data(base_dir: Path, scheme: str, operation: str, impl_mapping: dict) -> pd.DataFrame:
    """
    Extract pairing benchmark data from Criterion directories and return a DataFrame.
    
    Args:
        base_dir (Path): Base directory containing benchmark results.
        scheme (str): Cryptographic scheme name (e.g., "BLS12-381").
        operation (str): Operation being benchmarked (e.g., "pairing_product").
        impl_mapping (dict): Mapping of directory names to implementation names.
    Returns:
        pd.DataFrame: DataFrame containing benchmark data.
    """
    all_data = []
    
    # Check if base directory exists
    if not base_dir.exists():
        print(f"Error: Base directory {base_dir} does not exist!")
        return pd.DataFrame()
    
    for impl_dir in os.listdir(base_dir):
        if impl_dir in impl_mapping:
            impl_name = impl_mapping[impl_dir]
            impl_path = base_dir / impl_dir
            
            for size_dir in os.listdir(impl_path):
                try:
                    size = int(size_dir)  # Pairing size (e.g., 1, 2, 4, 8, 16, 32, 64)
                    report_dir = impl_path / size_dir / "new"
                    if report_dir.exists():
                        json_files = list(report_dir.glob("estimates.json"))
                        if json_files:
                            mean_ms = extract_mean_ms(json_files[0])
                            if mean_ms is not None:
                                all_data.append({
                                    "scheme": scheme,
                                    "operation": operation,
                                    "implementation": impl_name,
                                    "pairing_size": size,
                                    "mean_ms": mean_ms
                                })
                except ValueError:
                    # Skip non-integer directories (e.g., 'report')
                    continue
    
    if not all_data:
        print("No benchmark data found in the specified directory!")
        return pd.DataFrame()
    
    df = pd.DataFrame(all_data)
    return df.sort_values(["implementation", "pairing_size"])

def calculate_speedup(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate speedup ratios relative to the 'full' implementation.
    Adds a 'speedup' column to the DataFrame.
    
    Args:
        df (pd.DataFrame): DataFrame with benchmark data.
    Returns:
        pd.DataFrame: DataFrame with added 'speedup' column.
    """
    df['speedup'] = None
    
    for size in df['pairing_size'].unique():
        full_row = df[(df['implementation'] == 'full') & (df['pairing_size'] == size)]
        if not full_row.empty:
            full_time = full_row.iloc[0]['mean_ms']
            df.loc[full_row.index, 'speedup'] = 1.0
            
            for impl in ['miller', 'scaled']:
                impl_row = df[(df['implementation'] == impl) & (df['pairing_size'] == size)]
                if not impl_row.empty:
                    impl_time = impl_row.iloc[0]['mean_ms']
                    df.loc[impl_row.index, 'speedup'] = full_time / impl_time
    
    df['speedup'] = df['speedup'].astype(float)
    return df

def main():
    """Main function to extract benchmark data, calculate speedups, and save results."""
    print(f"Extracting benchmark data from {BASE_DIR}")
    benchmark_df = extract_benchmark_data(BASE_DIR, SCHEME, OPERATION, IMPL_MAPPING)
    
    if benchmark_df.empty:
        print("No data found. Please ensure benchmarks have been run.")
        return
    
    # Calculate speedup ratios
    benchmark_df = calculate_speedup(benchmark_df)
    
    # Save to CSV
    output_file = "pairing_benchmarks.csv"
    benchmark_df.to_csv(output_file, index=False)
    print(f"Benchmark data successfully saved to {output_file}")
    
    # Print summary statistics
    print("\nSummary of extracted data:")
    summary = benchmark_df.groupby(['operation', 'implementation']).agg({
        'mean_ms': ['min', 'max', 'mean'],
        'speedup': ['min', 'max', 'mean']
    })
    print(summary)
    
    print(f"\nDataset contains {benchmark_df.shape[0]} rows with "
          f"{len(benchmark_df['implementation'].unique())} implementations and "
          f"{len(benchmark_df['pairing_size'].unique())} different pairing sizes.")

if __name__ == "__main__":
    main()