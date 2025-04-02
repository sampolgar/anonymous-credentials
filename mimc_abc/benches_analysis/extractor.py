#!/usr/bin/env python3
import json
import pandas as pd
from pathlib import Path

# Define the base directory for Criterion benchmark results
BASE_DIR = Path("../../target/criterion/mimc_abc")

def extract_mean_ms(json_file: Path) -> float:
    """Extract the mean execution time in milliseconds from a Criterion JSON file."""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        mean_ns = data['mean']['point_estimate']  # Mean time in nanoseconds
        return mean_ns / 1_000_000  # Convert to milliseconds
    except (FileNotFoundError, KeyError) as e:
        print(f"Error processing {json_file}: {e}")
        return None

def extract_benchmark_data(base_dir: Path) -> pd.DataFrame:
    """Extract mimc_abc benchmark data from Criterion directories and return a DataFrame."""
    all_data = []
    
    # Check if base directory exists
    if not base_dir.exists():
        print(f"Error: Base directory {base_dir} does not exist!")
        return pd.DataFrame()
    
    # For each implementation (top-level directory)
    for impl_dir in base_dir.iterdir():
        if not impl_dir.is_dir():
            continue
        
        implementation = impl_dir.name
        
        # For each parameter set (subdirectory)
        for param_dir in impl_dir.iterdir():
            if not param_dir.is_dir():
                continue
            
            # Parse parameter information (e.g., "4creds_16attrs")
            param_name = param_dir.name
            if "creds_" in param_name and "attrs" in param_name:
                try:
                    creds = int(param_name.split("creds_")[0])
                    attrs = int(param_name.split("creds_")[1].split("attrs")[0])
                except (ValueError, IndexError):
                    print(f"Could not parse parameters from directory: {param_name}")
                    continue
                
                # Find the estimates.json file
                report_dir = param_dir / "new"
                if report_dir.exists():
                    json_file = report_dir / "estimates.json"
                    if json_file.exists():
                        mean_ms = extract_mean_ms(json_file)
                        if mean_ms is not None:
                            all_data.append({
                                "implementation": implementation,
                                "credential_count": creds,
                                "attribute_count": attrs,
                                "mean_ms": mean_ms
                            })
    
    if not all_data:
        print("No benchmark data found in the specified directory!")
        return pd.DataFrame()
    
    df = pd.DataFrame(all_data)
    return df.sort_values(["implementation", "credential_count", "attribute_count"])

def main():
    """Main function to extract benchmark data and save results."""
    print(f"Extracting benchmark data from {BASE_DIR}")
    benchmark_df = extract_benchmark_data(BASE_DIR)
    
    if benchmark_df.empty:
        print("No data found. Please ensure benchmarks have been run.")
        return
    
    # Save to CSV in current directory
    csv_file = "extracts/extract.csv"
    benchmark_df.to_csv(csv_file, index=False)
    print(f"Benchmark data successfully saved to {csv_file}")
    
    # Print basic information
    print(f"\nExtracted {benchmark_df.shape[0]} benchmark data points")
    print(f"Implementations: {benchmark_df['implementation'].unique()}")
    print(f"Credential counts: {sorted(benchmark_df['credential_count'].unique())}")
    print(f"Attribute counts: {sorted(benchmark_df['attribute_count'].unique())}")

if __name__ == "__main__":
    main()