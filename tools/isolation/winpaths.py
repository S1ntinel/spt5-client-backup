"""Read-only final-path and hardlink metadata; no hooks or filesystem mutation."""
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import stat

K = c.WinDLL("kernel32", use_last_error=True)


class FileInfo(c.Structure):
    _fields_ = [("attributes", w.DWORD), ("creation", w.FILETIME), ("access", w.FILETIME),
                ("write", w.FILETIME), ("volume", w.DWORD), ("size_hi", w.DWORD),
                ("size_lo", w.DWORD), ("links", w.DWORD), ("index_hi", w.DWORD), ("index_lo", w.DWORD)]


K.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, c.c_void_p]
K.CreateFileW.restype = w.HANDLE
K.CloseHandle.argtypes = [w.HANDLE]
K.GetFileInformationByHandle.argtypes = [w.HANDLE, c.POINTER(FileInfo)]
K.GetFinalPathNameByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD]


def identity(path):
    handle = K.CreateFileW(str(path), 0x80, 7, None, 3, 0x02000000, None)
    if handle == c.c_void_p(-1).value:
        raise c.WinError(c.get_last_error())
    try:
        info, text = FileInfo(), c.create_unicode_buffer(32768)
        if not K.GetFileInformationByHandle(handle, c.byref(info)):
            raise c.WinError(c.get_last_error())
        length = K.GetFinalPathNameByHandleW(handle, text, len(text), 0)
        if not length or length >= len(text):
            raise c.WinError(c.get_last_error())
        final = text.value
        if final.startswith("\\\\?\\UNC\\"):
            final = "\\\\" + final[8:]
        elif final.startswith("\\\\?\\"):
            final = final[4:]
        return Path(final), info.links
    finally:
        K.CloseHandle(handle)


def inside(path, root):
    try:
        return os.path.commonpath([os.path.normcase(str(path)), os.path.normcase(str(root))]) == os.path.normcase(str(root))
    except ValueError:
        return False


def normalized(path):
    if not path or not os.path.isabs(path):
        raise ValueError("必须提供显式绝对路径")
    if len(os.path.splitdrive(path)[0]) != 2:
        raise ValueError("只接受已确认的本地盘符路径，不接受设备命名空间或 UNC 别名")
    result = Path(os.path.abspath(path))
    for component in result.parts[1:]:
        if component.endswith((" ", ".")) or ":" in component or '"' in component:
            raise ValueError("拒绝歧义路径组件：" + component)
        base = component.split(".")[0].upper()
        if base in {"CON", "PRN", "AUX", "NUL", *("COM"+str(i) for i in range(1, 10)), *("LPT"+str(i) for i in range(1, 10))}:
            raise ValueError("拒绝设备路径：" + component)
    return result


def resolved(path):
    tail, existing = [], path
    while not os.path.lexists(existing):
        tail.append(existing.name)
        existing = existing.parent
    final, _ = identity(existing)
    if tail and not existing.is_dir():
        raise ValueError("目标父路径不是目录")
    return final.joinpath(*reversed(tail))


def no_links(path):
    for entry in [path, *path.parents]:
        if not os.path.lexists(entry):
            continue
        details = entry.stat(follow_symlinks=False)
        if details.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("拒绝重解析点／junction／symlink：" + str(entry))
        if entry.is_file() and identity(entry)[1] != 1:
            raise ValueError("拒绝共享硬链接文件：" + str(entry))
