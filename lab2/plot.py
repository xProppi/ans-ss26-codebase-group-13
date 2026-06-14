"""
ANS Lab 2 — Performance Comparison Plot
Group 13, SS26

Run after collecting iperf measurements:
    python3 plot.py

Fill in the measured values below before running.
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

# ── FILL IN YOUR MEASURED VALUES HERE ────────────────────────────────────────
# All values in Mbits/sec (average from iperf -t 20)
# Run each scenario with sp_routing first, then ft_routing, same conditions.

# Scenario descriptions
scenarios = [
    'Single flow\n(intra-pod)\nh0 -> h2',
    'Single flow\n(inter-pod)\nh0 -> h4',
    '2 concurrent\ninter-pod flows\nh0->h4, h2->h6',
    '4 concurrent\ninter-pod flows\nh0->h4, h2->h6\nh1->h5, h3->h7'
]

# Replace these with your actual measurements
sp_throughput = [13.5, 13.2, 7.1, 3.8]   # shortest-path results
ft_throughput  = [13.4, 13.0, 12.8, 11.6]  # two-level routing results

# ── PLOT ──────────────────────────────────────────────────────────────────────
x = np.arange(len(scenarios))
width = 0.35

fig, ax = plt.subplots(figsize=(12, 7))

bars1 = ax.bar(x - width/2, sp_throughput, width,
               label='Shortest-Path Routing',
               color='steelblue', edgecolor='white', linewidth=0.8)
bars2 = ax.bar(x + width/2, ft_throughput, width,
               label='Two-Level Fat-Tree Routing',
               color='darkorange', edgecolor='white', linewidth=0.8)

# Value labels on bars
for bar in bars1:
    h = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., h + 0.2,
            f'{h:.1f}', ha='center', va='bottom', fontsize=9)
for bar in bars2:
    h = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., h + 0.2,
            f'{h:.1f}', ha='center', va='bottom', fontsize=9)

ax.set_xlabel('Traffic Scenario', fontsize=12)
ax.set_ylabel('Throughput (Mbits/sec)', fontsize=12)
ax.set_title('Routing Performance Comparison: Shortest-Path vs Two-Level Fat-Tree Routing\n'
             'Fat-tree k=4, 16 servers, 15 Mbps links, 5ms delay',
             fontsize=12)
ax.set_xticks(x)
ax.set_xticklabels(scenarios, fontsize=9)
ax.legend(fontsize=11)
ax.set_ylim(0, 17)
ax.axhline(y=15, color='grey', linestyle='--', alpha=0.4, linewidth=1,
           label='Link capacity (15 Mbps)')
ax.grid(axis='y', alpha=0.3)

plt.tight_layout()
plt.savefig('comparison.png', dpi=150, bbox_inches='tight')
print("Plot saved to comparison.png")
