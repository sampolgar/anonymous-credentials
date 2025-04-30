import matplotlib.pyplot as plt

# Data
attribute_counts = [2, 5, 10, 15, 20, 30]

# Operation data
data = {
    "Obtain": {
        "ASM06": [0.51, 0.65, 0.67, 0.78, 0.86, 1.07],
        "CDL16": [0.90, 1.00, 1.13, 1.26, 1.38, 1.63],
        "PS16":  [0.66, 0.66, 0.82, 0.87, 0.94, 1.11],
        "TBA+22": [0.25, 0.28, 0.36, 0.37, 0.41, 0.51],
        "Our Construction": [0.23, 0.27, 0.31, 0.36, 0.41, 0.49]
    },
    "Issue": {
        "ASM06": [1.25, 1.66, 2.33, 2.98, 3.96, 4.97],
        "CDL16": [0.72, 0.75, 0.83, 0.84, 0.90, 0.94],
        "PS16":  [1.48, 1.79, 2.54, 3.23, 3.79, 5.16],
        "TBA+22": [1.27, 1.66, 2.35, 3.03, 3.66, 5.10],
        "Our Construction": [2.99, 3.31, 4.00, 4.64, 5.88, 6.86]
    },
    "Show": {
        "ASM06": [5.39, 6.05, 7.44, 8.86, 11.88, 12.91],
        "CDL16": [2.31, 2.42, 1.71, 2.71, 1.88, 3.15],
        "PS16":  [3.20, 3.15, 4.53, 6.14, 7.66, 16.23],
        "TBA+22": [1.14, 1.16, 1.22, 1.40, 1.41, 1.37],
        "Our Construction": [1.29, 1.29, 1.33, 1.37, 1.51, 1.59]
    },
    "Verify": {
        "ASM06": [7.59, 9.25, 11.09, 13.96, 16.93, 26.30],
        "CDL16": [2.18, 2.25, 2.25, 2.30, 2.34, 2.57],
        "PS16":  [4.57, 5.52, 7.10, 8.62, 9.88, 16.55],
        "TBA+22": [2.47, 2.73, 3.16, 3.47, 3.84, 4.67],
        "Our Construction": [1.79, 2.01, 2.44, 2.72, 3.21, 3.79]
    },
    "Obtain+Issue total": {
        "ASM06": [1.76, 2.31, 3.00, 3.75, 4.82, 6.04],
        "CDL16": [1.62, 1.76, 1.96, 2.10, 2.29, 2.57],
        "PS16":  [2.14, 2.45, 3.37, 4.10, 4.74, 6.27],
        "TBA+22": [1.53, 1.95, 2.71, 3.40, 4.06, 5.60],
        "Our Construction": [3.22, 3.57, 4.31, 5.00, 6.28, 7.35]
    },
    "Show+Verify total": {
        "ASM06": [12.98, 15.30, 18.53, 22.82, 28.81, 39.21],
        "CDL16": [4.48, 4.67, 3.96, 4.22, 5.01, 5.72],
        "PS16":  [7.77, 8.68, 11.62, 14.76, 17.53, 32.77],
        "TBA+22": [3.61, 3.90, 4.38, 4.87, 5.25, 6.04],
        "Our Construction": [3.08, 3.30, 3.77, 4.09, 4.72, 5.37]
    }
}

# Color scheme
colors = {
    "ASM06": "#C2C9D1",       
    "CDL16": "#D6BC8E",       
    "PS16":  "#4A90E2",       
    "TBA+22": "#21305F",      
    "Our Construction": "#E45932"
}

# Generate separate figures for each operation
for op_name, op_data in data.items():
    plt.figure(figsize=(6, 4))
    for label, timings in op_data.items():
        plt.plot(attribute_counts, timings, marker='o', label=label, color=colors[label])
    plt.title(f'{op_name} Operation')
    plt.xlabel('Number of Attributes')
    plt.ylabel('Time (ms)')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()


# Light Blue: #4A90E2
# Dark Navy Blue: #21305F
# Orange-Red: #E45932
# Beige/Tan: #D6BC8E
# Light Gray: #C2C9D1