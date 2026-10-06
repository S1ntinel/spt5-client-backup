import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import sys
import tempfile
import uuid

from winpaths import inside, no_links, normalized, resolved

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[1]
REPORT = WORKSPACE / "outputs/Live-SPT-isolation-stage2-20261004"


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


class Guard:
    def __init__(self, policy):
        self.policy = policy
        self.protected = [normalized(p) for p in policy["protected_roots"]]
        self.allowed = [normalized(p) for p in policy["spt_roots"]]
        if not self.protected or not self.allowed:
            raise ValueError("保护路径与 SPT 白名单不可为空")

    def path(self, value, allow_spt=True):
        path = normalized(str(value))
        final = resolved(path)
        blocked = self.protected + ([] if allow_spt else self.allowed)
        # 测试或管理员只能增加拒绝目录，不能删除 policy.json 的保护目录。
        blocked += [normalized(p) for p in os.environ.get("SPT_GUARD_EXTRA_DENY", "").split(os.pathsep) if p]
        for root in blocked:
            if inside(path, root) or inside(final, resolved(root)):
                raise ValueError("拒绝官方／受保护安装目录：" + str(final))
        no_links(path)
        for ancestor in [path, *path.parents]:
            if ancestor.is_dir() and (ancestor/"LIVE_PROTECTED_DO_NOT_MODIFY.txt").exists():
                raise ValueError("目标路径链含 Live 保护标记：" + str(ancestor))
        return path

    def root(self, value, require_marker=True):
        root = self.path(value)
        if not root.is_dir() or not any(os.path.samefile(root, p) for p in self.allowed if p.exists()):
            raise ValueError("SPT_DEPLOY_ROOT 不在已确认白名单：" + str(root))
        for marker in self.policy["live_only_markers"]:
            if (root/marker).exists():
                raise ValueError("目标含 Live-only 标志：" + marker)
        for marker in ("EscapeFromTarkov.exe", "BepInEx", "SPT_Runtime/SPT.Server.exe"):
            if not (root/marker).exists():
                raise ValueError("目标缺少 SPT 安装标志：" + marker)
            self.path(root/marker)
        token = root/self.policy["marker"]
        self.path(token)
        if require_marker and (not token.is_file() or token.read_text(encoding="utf-8-sig").strip() != self.policy["marker_content"]):
            raise ValueError("缺少有效 SPT 开发标记：" + str(token))
        return root

    def tree(self, root, allow_spt=True):
        self.path(root, allow_spt)
        if root.is_dir():
            for directory, folders, files in os.walk(root, followlinks=False):
                for name in folders + files:
                    self.path(Path(directory)/name, allow_spt)

    def processes(self, processes, root, deploy=False):
        for process in processes:
            name, exe = process.get("Name", ""), process.get("ExecutablePath") or ""
            if deploy and name.lower() in {"dotnet.exe", "mono.exe"} and re.search(r"spt[._-](?:server|launcher)\.(?:dll|exe)", process.get("CommandLine") or "", re.I):
                raise ValueError("请先退出由 dotnet/mono 承载的 SPT 组件，再部署")
            if name.lower() == "escapefromtarkov.exe":
                if not exe or any(inside(exe, p) for p in self.protected):
                    raise ValueError("Live 客户端运行中或路径无法确认")
                if deploy and inside(exe, root):
                    raise ValueError("请先正常退出目标 SPT 客户端，再部署")
            if deploy and exe and inside(exe, root) and name.lower() in {"spt.server.exe", "spt.launcher.exe"}:
                raise ValueError("请先退出目标 SPT Server/Launcher，再部署")

    def plan(self, root, package):
        root = self.root(str(root))
        package = self.path(package, allow_spt=False)
        if not package.is_dir() or not inside(package, WORKSPACE):
            raise ValueError("安装包必须位于当前开发工作区")
        self.tree(package, allow_spt=False)
        plan, seen = [], set()
        for source in sorted(package.rglob("*")):
            if not source.is_file():
                continue
            self.path(source, allow_spt=False)
            rel = source.relative_to(package)
            parts = [p.lower() for p in rel.parts]
            client = len(parts) >= 4 and parts[:2] == ["bepinex", "plugins"]
            server = len(parts) >= 5 and parts[:3] == ["spt_runtime", "user", "mods"]
            if not (client or server):
                raise ValueError("安装包只能写 BepInEx/plugins/<mod> 或 SPT_Runtime/user/mods/<mod>：" + str(rel))
            if (client and parts[2] == "sptushonka") or source.name.lower() in {"assembly-csharp.dll", "gameassembly.dll", "unityplayer.dll", "sptarkov.server.core.dll", "bepinex.core.dll"}:
                raise ValueError("此模组入口不用于覆盖核心程序集：" + str(rel))
            key = str(rel).casefold()
            if key in seen:
                raise ValueError("安装包包含大小写冲突路径：" + str(rel))
            seen.add(key)
            target = self.path(root/rel)
            if target.exists() and not target.is_file():
                raise ValueError("目标文件路径被目录占用：" + str(target))
            if not inside(resolved(target), resolved(root)):
                raise ValueError("部署目标逃逸 SPT 根目录")
            plan.append({"relative_path": rel.as_posix(), "source": str(source), "target": str(target), "sha256": sha(source)})
        if not plan:
            raise ValueError("安装包为空")
        return plan


def apply(guard, root, plan, backup_root):
    guard.path(backup_root, allow_spt=False)
    backup_root.mkdir(parents=True, exist_ok=False)
    journal = []
    # 全部旧文件先备份，再进行任何安装写入。
    for entry in plan:
        target = guard.path(entry["target"])
        old = backup_root/entry["relative_path"]
        if target.exists():
            old.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(target, old)
        journal.append({**entry, "backup": str(old) if target.exists() else None, "installed": False})
    manifest = backup_root/"deployment.json"
    manifest.write_text(json.dumps(journal, ensure_ascii=False, indent=2), encoding="utf-8")
    for entry in journal:
        target = guard.path(entry["target"])
        target.parent.mkdir(parents=True, exist_ok=True)
        guard.path(target.parent)
        temp = None
        try:
            with tempfile.NamedTemporaryFile(prefix="SPTDEPLOY-", suffix=".tmp", dir=target.parent, delete=False) as handle:
                temp = Path(handle.name)
            shutil.copyfile(entry["source"], temp)
            if sha(temp) != entry["sha256"]:
                raise ValueError("源文件在部署期间变化，拒绝替换：" + entry["source"])
            guard.path(target)
            os.replace(temp, target)
            entry["installed"] = True
            manifest.write_text(json.dumps(journal, ensure_ascii=False, indent=2), encoding="utf-8")
        finally:
            if temp and temp.exists():
                temp.unlink()
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["root", "launch", "deploy", "build", "init-markers"])
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    guard = Guard(json.loads((HERE/"policy.json").read_text(encoding="utf-8-sig")))
    if args.mode == "build":
        project = guard.path(os.environ["SPT_GUARD_PROJECT"], allow_spt=False)
        for key in ("OUTPUT", "OUTDIR", "TARGETDIR", "TARGETPATH", "BASEOUTPUT", "PACKAGEOUTPUT", "ARTIFACTS", "INTERMEDIATE", "BASEINTERMEDIATE", "EXTENSIONS", "PUBLISH", "BUILDROOT", "PROJECTDIR"):
            value = os.environ.get("SPT_GUARD_" + key)
            if value:
                candidate = Path(value) if os.path.isabs(value) else project/value
                guard.tree(candidate, allow_spt=False)
        if os.environ.get("SPT_DEPLOY_ROOT"):
            guard.root(os.environ["SPT_DEPLOY_ROOT"])
        print("SPT BUILD OUTPUT CHECK: PASS (no deployment)")
        return
    if args.mode == "init-markers":
        for configured in guard.allowed:
            root = guard.root(str(configured), require_marker=False)
            token = root/guard.policy["marker"]
            if token.exists() and token.read_text(encoding="utf-8-sig").strip() != guard.policy["marker_content"]:
                raise ValueError("已有标记内容不同，拒绝覆盖")
            if not token.exists():
                token.write_text(guard.policy["marker_content"] + "\n", encoding="utf-8")
            print("SPT marker: " + str(token))
        return
    root = guard.root(os.environ.get("SPT_GUARD_ROOT", ""))
    if args.mode == "root":
        print("SPT ROOT CHECK: PASS " + str(root))
        return
    processes = json.loads(sys.stdin.read().lstrip("\ufeff"))
    if args.mode == "launch" or args.apply:
        guard.processes(processes, root, deploy=args.mode == "deploy")
    if args.mode == "launch":
        guard.tree(root)
        config = root/"SPT_Runtime/user/Launcher/LauncherSettings.json"
        guard.path(config)
        settings = json.loads(config.read_text(encoding="utf-8-sig"))
        if settings.get("EnableGamePath") is not True or guard.root(settings.get("GamePath", "")) != root:
            raise ValueError("Launcher 必须明确指向同一 SPT 根目录")
        for filename in ("EscapeFromTarkov.exe", "SPT_Runtime/SPT.Server.exe", "SPT_Runtime/SPT.Launcher.exe"):
            guard.path(root/filename)
        print("SPT PREFLIGHT: PASS")
        return
    plan = guard.plan(root, os.environ.get("SPT_GUARD_PACKAGE", ""))
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    if args.apply:
        backup = REPORT/"deployment-backups"/(datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])
        manifest = apply(guard, root, plan, backup)
        print("SPT DEPLOY: PASS; backup=" + str(manifest))
    else:
        print("SPT DEPLOY: DRY RUN; no game files changed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        print("SPT GUARD: FAIL - " + str(error), file=sys.stderr)
        raise SystemExit(1)
