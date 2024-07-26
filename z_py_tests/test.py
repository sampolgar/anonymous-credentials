import os
import json
import csv
from typing import List, Dict

def find_criterion_results(root_dir: str) -> List[str]:
    """Find all Criterion result directories."""
    results = []
    for root, dirs, files in os.walk(root_dir):
        if 'new' in dirs:
            results.append(os.path.join(root, 'new'))
    return results

def parse_criterion_json(directory: str) -> Dict:
    """Parse Criterion JSON files and extract relevant information."""
    benchmark_file = os.path.join(directory, 'benchmark.json')
    estimates_file = os.path.join(directory, 'estimates.json')
    
    with open(benchmark_file, 'r') as f:
        benchmark_data = json.load(f)
    
    with open(estimates_file, 'r') as f:
        estimates_data = json.load(f)
    
    return {
        "test_name": benchmark_data.get("group_id", "Unknown"),
        "subtest_name": benchmark_data.get("value_str", "Unknown"),
        "mean": estimates_data.get("mean", {}).get("point_estimate", 0)
    }

def extract_all_results(root_dir: str) -> List[Dict]:
    """Extract results from all Criterion result directories."""
    result_dirs = find_criterion_results(root_dir)
    return [parse_criterion_json(directory) for directory in result_dirs]

def write_to_csv(data: List[Dict], output_file: str):
    """Write the extracted data to a CSV file."""
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)

def main():
    root_dir = "target/criterion"  # Adjust this if your path is different
    results = extract_all_results(root_dir)
    write_to_csv(results, "criterion_results.csv")
    print(f"Results written to criterion_results.csv")

if __name__ == "__main__":
    main()