"""저장소에 개인키가 커밋됐는지 찾는다. 내용은 절대 출력하지 않고 위치(파일·줄·커밋)만 보인다.

    ../.venv/bin/python secret_scan.py out/fake-repo

- 작업 트리: 지금 있는 파일
- 이력: git log -p 로 과거 커밋에 들어갔던 줄(지운 파일도 이력에는 남는다)
실무에서는 gitleaks·trufflehog 같은 전용 도구와 저장소 호스팅의 비밀값 검사(push 보호)를 함께 쓴다.
"""
import re
import subprocess
import sys
from pathlib import Path

# PEM 머리줄을 조각으로 이어 붙인다(이 파일 자체가 검사에 걸리지 않게).
PEM_KEY = re.compile("-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?" + "PRIVATE" + " KEY-----")
TOKEN = re.compile(r"(?i)^\s*[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|API_KEY)\s*=\s*\S+")
KEY_FILE_NAMES = re.compile(r"(?i)(\.key|\.p12|\.pfx|id_rsa|id_ecdsa|id_ed25519)$")

def scan_tree(root: Path):
    hits = []
    for p in sorted(root.rglob("*")):
        if ".git" in p.parts or not p.is_file():
            continue
        rel = p.relative_to(root)
        if KEY_FILE_NAMES.search(p.name):
            hits.append(("작업 트리", str(rel), "-", "키 파일 이름"))
        try:
            lines = p.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            if PEM_KEY.search(line):
                hits.append(("작업 트리", str(rel), i, "개인키 PEM 머리줄"))
            elif TOKEN.search(line):
                hits.append(("작업 트리", str(rel), i, "비밀값처럼 보이는 키=값"))
    return hits

def scan_history(root: Path):
    out = subprocess.run(["git", "-C", str(root), "log", "-p", "--all", "--format=@@COMMIT %h %s", "--no-color"],
                         capture_output=True, text=True, check=True).stdout
    hits, commit, path = [], None, None
    for line in out.splitlines():
        if line.startswith("@@COMMIT "):
            commit = line.split()[1] + " " + " ".join(line.split()[2:])
        elif line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("--- a/") and path is None:
            path = line[6:]
        elif line.startswith("diff --git"):
            path = None
        elif line.startswith("+") and not line.startswith("+++ ") and PEM_KEY.search(line):
            hits.append(("이력(추가)", path, commit, "개인키 PEM 머리줄"))
        elif line.startswith("-") and not line.startswith("--- ") and PEM_KEY.search(line):
            hits.append(("이력(삭제)", path or "?", commit, "개인키 PEM 머리줄"))
    return hits

if __name__ == "__main__":
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "out/fake-repo")
    tree, hist = scan_tree(root), scan_history(root)
    print(f"검사 대상: {root}")
    print(f"[작업 트리] {len(tree)}건")
    for where, path, line, kind in tree:
        print(f"  {path}:{line}  {kind}")
    print(f"[이력] {len(hist)}건")
    for where, path, commit, kind in hist:
        print(f"  {where:7} {path}  커밋 {commit}  {kind}")
    print("내용은 출력하지 않았습니다. 찾은 키는 '지우기'가 아니라 '폐기·교체' 대상입니다.")
    sys.exit(1 if (tree or hist) else 0)
