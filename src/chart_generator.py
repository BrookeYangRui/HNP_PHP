#!/usr/bin/env python3
import argparse
import os
import sys
import csv


PROJECT_ROOT = "/home/rui/HNP_PHP"
CSV_DIR = os.path.join(PROJECT_ROOT, "reports", "csv")
FIG_DIR = os.path.join(PROJECT_ROOT, "reports", "figures")
LATEX_DIR = os.path.join(PROJECT_ROOT, "reports", "tex")


def ensure_dirs() -> None:
    os.makedirs(FIG_DIR, exist_ok=True)
    os.makedirs(LATEX_DIR, exist_ok=True)


def try_imports():
    try:
        import pandas as pd  # noqa: F401
        import matplotlib  # noqa: F401
        import seaborn  # noqa: F401
        return True
    except Exception as e:
        print(f"Python plotting deps missing: {e}")
        return False


def generate_charts():
    import pandas as pd
    import seaborn as sns
    import matplotlib.pyplot as plt

    detailed_path = os.path.join(CSV_DIR, "flow_api_risk_detailed.csv")
    summary_path = os.path.join(CSV_DIR, "flow_summary.csv")

    if not os.path.exists(summary_path):
        print("No summary CSV found; skip charts")
        return

    # Stacked bar: Risk/Partial/Protected/Safe per framework
    df_sum = pd.read_csv(summary_path)
    # long-form
    melt = df_sum.melt(id_vars=["Framework", "Sources", "Sinks"],
                       value_vars=["Risk", "Partial", "Protected", "Safe"],
                       var_name="State", value_name="Count")
    plt.figure(figsize=(10, 5))
    sns.barplot(data=melt, x="Framework", y="Count", hue="State")
    plt.title("Framework Security States (Stacked)")
    plt.xlabel("")
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "states_bar.png"), dpi=200)
    plt.savefig(os.path.join(FIG_DIR, "states_bar.svg"))
    plt.close()

    # Heatmap: Protected_Rate per (Framework, Canonical_API)
    if os.path.exists(detailed_path):
        df_det = pd.read_csv(detailed_path)
        # Coerce Protected_Rate
        def _to_float(x):
            try:
                return float(x)
            except Exception:
                return 0.0
        df_det["Protected_Rate"] = df_det["Protected_Rate"].apply(_to_float)
        pivot = df_det.pivot_table(index="Framework", columns="Canonical_API", values="Protected_Rate", aggfunc="mean").fillna(0.0)
        plt.figure(figsize=(max(6, 0.5 * len(pivot.columns)), 4 + 0.4 * len(pivot.index)))
        sns.heatmap(pivot, annot=False, cmap="YlOrRd", vmin=0, vmax=1)
        plt.title("Protected Rate Heatmap (Framework x API)")
        plt.tight_layout()
        plt.savefig(os.path.join(FIG_DIR, "protected_heatmap.png"), dpi=200)
        plt.savefig(os.path.join(FIG_DIR, "protected_heatmap.svg"))
        plt.close()


def generate_latex_tables():
    detailed_path = os.path.join(CSV_DIR, "flow_api_risk_detailed.csv")
    if not os.path.exists(detailed_path):
        print("No detailed CSV found; skip LaTeX table")
        return
    # Minimal LaTeX table from CSV
    with open(detailed_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    cols = [
        ("Framework", "Framework"),
        ("Canonical_API", "API"),
        ("Category", "Cat"),
        ("Total", "Total"),
        ("Guarded", "Guarded"),
        ("Unguarded", "Unguarded"),
        ("Protected_Rate", "Prot"),
        ("Security_State", "State"),
    ]

    tex_path = os.path.join(LATEX_DIR, "framework_api_risk_table.tex")
    with open(tex_path, "w", encoding="utf-8") as out:
        out.write("% Auto-generated LaTeX table for IEEE S&P\n")
        out.write("\\begin{table}[t]\n\\centering\n")
        out.write("\\small\n")
        out.write("\\begin{tabular}{l l l r r r r l}\n")
        out.write("\\toprule\n")
        header = " ".join(["{" + h + "}" for _, h in cols])
        out.write("Framework & API & Cat & Total & Guarded & Unguarded & Prot & State\\\\\\n")
        out.write("\\midrule\n")
        for r in rows:
            vals = [r.get(k, "") for k, _ in cols]
            # escape
            vals = [str(v).replace("_", "\\_") for v in vals]
            out.write("{} & {} & {} & {} & {} & {} & {} & {}\\\\\n".format(*vals))
        out.write("\\bottomrule\n\\end{tabular}\n\\caption{Framework API Risk Summary}\n\\label{tab:framework-api-risk}\n\\end{table}\n")


def main():
    ensure_dirs()
    parser = argparse.ArgumentParser(description="Generate IEEE S&P style charts and LaTeX tables")
    parser.add_argument("--only-latex", action="store_true")
    args = parser.parse_args()

    have_libs = try_imports()
    if not args.only_latex and have_libs:
        generate_charts()
    generate_latex_tables()
    print("✅ 图表与表格生成完成")


if __name__ == "__main__":
    main()


