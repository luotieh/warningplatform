"""Build a lightweight dependency graph for the warning platform repository.

The output is intentionally tool-agnostic: JSON contains graph/vector metadata and
Mermaid renders the architecture overview in any Markdown viewer.
"""
from __future__ import annotations
import json, re, os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "codegraph"
SKIP = {"node_modules", ".git", "dist", "build", "coverage"}
EXTS = {".go", ".ts", ".tsx", ".vue", ".js", ".jsx", ".py"}

def rel(p: Path) -> str:
    return p.relative_to(ROOT).as_posix()

def main() -> None:
    files = []
    for base, dirs, names in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for name in names:
            p = Path(base) / name
            if p.suffix in EXTS: files.append(p)
    nodes = []
    for p in files:
        text = p.read_text(encoding="utf-8", errors="ignore")
        lang = {".go":"go", ".ts":"typescript", ".tsx":"typescript", ".vue":"vue", ".js":"javascript", ".jsx":"javascript", ".py":"python"}[p.suffix]
        # A compact feature vector useful for clustering/search: file size, lines,
        # imports, exported declarations, and language one-hot flags.
        imports = len(re.findall(r"(?m)^\s*(?:import|from|require\(|#include)", text))
        exports = len(re.findall(r"(?m)^\s*(?:export\s+|func\s+[A-Z]|type\s+[A-Z]|class\s+)", text))
        lines = text.count("\n") + 1
        nodes.append({"id": rel(p), "language": lang, "lines": lines, "bytes": p.stat().st_size,
                      "imports": imports, "exports": exports,
                      "vector": [lines, p.stat().st_size, imports, exports, int(lang=="go"), int(lang in ("typescript","vue","javascript"))]})
    node_ids = {n["id"] for n in nodes}
    edges = set()
    for n in nodes:
        p = ROOT / n["id"]
        text = p.read_text(encoding="utf-8", errors="ignore")
        for s in re.findall(r"(?:from|import)\s+[\"']([^\"']+)", text):
            if s.startswith("."):
                base = (p.parent / s).resolve()
                candidates = [base, *[base.with_suffix(e) for e in EXTS], base / "index.ts", base / "index.js"]
                for c in candidates:
                    try: rid = rel(c)
                    except ValueError: continue
                    if rid in node_ids: edges.add((n["id"], rid)); break
    OUT.mkdir(parents=True, exist_ok=True)
    data = {"root": str(ROOT), "nodes": nodes, "edges": [{"source":a,"target":b} for a,b in sorted(edges)]}
    (OUT / "graph.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = ["# CodeGraph 总览", "", f"节点：{len(nodes)}，边：{len(edges)}", "", "```mermaid", "graph LR"]
    groups = {}
    for n in nodes:
        top = n["id"].split("/")[0]
        groups.setdefault(top, []).append(n)
    for i, (g, ns) in enumerate(sorted(groups.items())):
        gid = f"G{i}"; lines.append(f"  subgraph {gid}[{g}]")
        for n in sorted(ns, key=lambda x:x["id"])[:80]:
            nid = "N" + str(abs(hash(n["id"])))
            lines.append(f"    {nid}[{n['id'].split('/')[-1]}]")
        lines.append("  end")
    lookup = {n["id"]:"N"+str(abs(hash(n["id"]))) for n in nodes}
    for a,b in sorted(edges):
        if a in lookup and b in lookup: lines.append(f"  {lookup[a]} --> {lookup[b]}")
    lines += ["```", "", "`graph.json` 中每个文件包含可用于聚类/检索的轻量特征向量。"]
    (OUT / "README.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"generated {len(nodes)} nodes, {len(edges)} edges in {OUT}")

if __name__ == "__main__": main()
