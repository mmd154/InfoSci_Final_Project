

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

labels = ["SHA-256\n(unsalted)", "bcrypt\n(work factor 12)"]
times_seconds = [0.000481, 208]   
annotations = ["0.481 ms", "208 s"]  
slowdown_text = "497,607x slowdown"  
chart_title = "Crack Time Before vs. After Countermeasure"
output_path = "crack_time_comparison.png"

colors = ["#4C72B0", "#DD8452"]

fig, ax = plt.subplots(figsize=(6.5, 4.5))
bars = ax.bar(labels, times_seconds, color=colors, width=0.5)

ax.set_yscale("log")
ax.set_ylabel("Average time to identify weak password (s, log scale)")
ax.set_title(chart_title, pad=20)

# Add headroom above the tallest bar so its label doesn't collide with the title
ax.set_ylim(top=max(times_seconds) * 10)

for bar, label in zip(bars, annotations):
    height = bar.get_height()
    ax.annotate(label,
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 6),
                textcoords="offset points",
                ha="center", va="bottom", fontsize=11, fontweight="bold")

if slowdown_text:
    ax.annotate(slowdown_text,
                xy=(0.5, 0.9), xycoords="axes fraction",
                ha="center", fontsize=10, style="italic", color="dimgray")

ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y, _: f"{y:g}"))
ax.grid(axis="y", which="both", linestyle="--", alpha=0.4)
ax.set_axisbelow(True)

plt.tight_layout()
plt.savefig(output_path, dpi=300)
print(f"Saved chart to {output_path}")
