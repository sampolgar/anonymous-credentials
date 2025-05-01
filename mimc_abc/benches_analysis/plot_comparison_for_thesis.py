import matplotlib.pyplot as plt

# Data
creds = [4, 16, 32]
single_np = [2.87, 10.08, 19.55]
single_p  = [7.11, 25.85, 50.64]
multi_np  = [6.79, 27.45, 57.88]
multi_p   = [17.65, 72.57, 147.35]

# Colors and styles
color_non = "#4A90E2"  # non-private multi-issuer color
color_priv = "#E45932"  # private color

# 1. Single-Issuer: Private vs Non-Private with annotations
plt.figure(figsize=(6, 4))
plt.plot(creds, single_p,  marker='o', label='Private Single-Issuer',     color=color_priv, linestyle='-')
plt.plot(creds, single_np, marker='o', label='Non-Private Single-Issuer', color=color_non, linestyle='-')
plt.plot([], [], ' ', label='2.x = Privacy Overhead')


# Annotate overhead ratios
for x, np_t, p_t in zip(creds, single_np, single_p):
    ratio = p_t / np_t
    plt.text(x, p_t + 2, f'{ratio:.1f}×', ha='center')

plt.title('Single-Issuer: Privacy Overhead')
plt.xlabel('Credential Count')
plt.ylabel('Verification Time (ms)')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()

# 2. Multi-Issuer: Private vs Non-Private (privacy overhead)
plt.figure(figsize=(6, 4))
plt.plot(creds, multi_p,  marker='o', label='Private Multi-Issuer',     color=color_priv, linestyle='-')
plt.plot(creds, multi_np, marker='o', label='Non-Private Multi-Issuer', color=color_non, linestyle='-')
plt.plot([], [], ' ', label='2.x = Privacy Overhead')  

# Annotate overhead ratios
for x, np_t, p_t in zip(creds, multi_np, multi_p):
    ratio = p_t / np_t
    plt.text(x, p_t + 4, f'{ratio:.1f}×', ha='center')

plt.title('Multi-Issuer: Privacy Overhead')
plt.xlabel('Credential Count')
plt.ylabel('Verification Time (ms)')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()

# 3. Single-Issuer vs Multi-Issuer with annotations
plt.figure(figsize=(6, 4))
plt.plot(creds, multi_p,  marker='o', label='Private Multi-Issuer',      color=color_priv, linestyle='-')
plt.plot(creds, single_p, marker='o', label='Private Single-Issuer',     color=color_priv, linestyle=':')
plt.plot([], [], ' ', label='2.x = Speedup from Batch Verify')  

# Annotate overhead ratios
for x, mp_t, sp_t in zip(creds, multi_p, single_p):
    ratio = mp_t / sp_t
    plt.text(x, sp_t + 2, f'{ratio:.1f}×', ha='center')

plt.title('Private - Speedup from Batch Verify')
plt.xlabel('Credential Count')
plt.ylabel('Verification Time (ms)')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()

# 4. Single-Issuer vs Multi-Issuer with annotations
plt.figure(figsize=(6, 4))
# Non-private lines
plt.plot(creds, multi_np, marker='o', label='Non-Private Multi-Issuer',   color=color_non, linestyle='-')
plt.plot(creds, single_np, marker='o', label='Non-Private Single-Issuer', color=color_non, linestyle=':')
plt.plot([], [], ' ', label='2.x = Speedup from Batch Verify')  

# Annotate overhead ratios
for x, mnp_t, snp_t in zip(creds, multi_np, single_np):
    ratio = mnp_t / snp_t
    plt.text(x, snp_t +2, f'{ratio:.1f}×', ha='center')

plt.title('Non Private - Speedup from Batch Verify')
plt.xlabel('Credential Count')
plt.ylabel('Verification Time (ms)')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()









# # 3. Issuer-Model Comparison with dotted vs solid
# # Private lines
# plt.figure(figsize=(6, 4))
# plt.plot(creds, multi_p,  marker='o', label='Private Multi-Issuer',      color=color_priv, linestyle='-')
# plt.plot(creds, single_p, marker='o', label='Private Single-Issuer',     color=color_priv, linestyle=':')

# # Non-private lines
# plt.plot(creds, multi_np, marker='o', label='Non-Private Multi-Issuer',   color=color_non, linestyle='-')
# plt.plot(creds, single_np, marker='o', label='Non-Private Single-Issuer', color=color_non, linestyle=':')


# plt.title('Multi-Credential Verification')
# plt.xlabel('Credential Count')
# plt.ylabel('Verification Time (ms)')
# plt.legend()
# plt.grid(True)
# plt.tight_layout()
# plt.show()
