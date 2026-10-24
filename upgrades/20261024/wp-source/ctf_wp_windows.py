"""Actual target-window capture, isolated in a bounded child process."""
import argparse
import ctypes
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import subprocess
import sys


def capture_window(output, process_id=None, executable=None):
    if os.name != 'nt':
        raise ValueError('Windows window capture requires Windows')
    if process_id is None and not executable:
        raise ValueError('Provide an explicit target process_id')
    output = Path(output).resolve()
    command = [sys.executable, '-X', 'utf8', str(Path(__file__).resolve()), '--output', str(output)]
    if process_id is not None:
        if type(process_id) is not int or process_id < 1:
            raise ValueError('process_id must be a positive integer')
        command += ['--pid', str(process_id)]
    if executable:
        command += ['--executable', str(Path(executable).resolve())]
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', timeout=12,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except subprocess.TimeoutExpired:
        raise RuntimeError('Target-window capture timed out; original action was not repeated') from None
    if result.returncode:
        raise RuntimeError(result.stderr[-1000:] or result.stdout[-1000:] or 'Window capture failed')
    return json.loads(result.stdout)


def native_capture(output, pid, executable):
    from PIL import Image, ImageStat
    user, gdi, kernel = ctypes.windll.user32, ctypes.windll.gdi32, ctypes.windll.kernel32
    try: ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception: pass
    user.GetWindowThreadProcessId.argtypes = [W.HWND, ctypes.POINTER(W.DWORD)]
    user.GetWindowRect.argtypes = [W.HWND, ctypes.POINTER(W.RECT)]
    user.IsWindowVisible.argtypes = [W.HWND]; user.IsWindowVisible.restype = W.BOOL
    user.IsIconic.argtypes = [W.HWND]; user.IsIconic.restype = W.BOOL
    user.GetDC.argtypes = [W.HWND]; user.GetDC.restype = W.HDC
    user.ReleaseDC.argtypes = [W.HWND, W.HDC]
    user.PrintWindow.argtypes = [W.HWND, W.HDC, W.UINT]
    gdi.CreateCompatibleDC.argtypes = [W.HDC]; gdi.CreateCompatibleDC.restype = W.HDC
    gdi.CreateCompatibleBitmap.argtypes = [W.HDC, ctypes.c_int, ctypes.c_int]; gdi.CreateCompatibleBitmap.restype = W.HANDLE
    gdi.SelectObject.argtypes = [W.HDC, W.HANDLE]; gdi.SelectObject.restype = W.HANDLE
    gdi.DeleteObject.argtypes = [W.HANDLE]; gdi.DeleteDC.argtypes = [W.HDC]
    gdi.GetDIBits.argtypes = [W.HDC, W.HANDLE, W.UINT, W.UINT, ctypes.c_void_p, ctypes.c_void_p, W.UINT]
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]; kernel.OpenProcess.restype = W.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, ctypes.POINTER(W.DWORD)]
    kernel.CloseHandle.argtypes = [W.HANDLE]
    expected = str(Path(executable).resolve()).casefold() if executable else None
    found = []
    callback_type = ctypes.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
    user.EnumWindows.argtypes = [callback_type, W.LPARAM]; user.EnumWindows.restype = W.BOOL
    def visit(hwnd, _):
        owner = W.DWORD(); user.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if pid and owner.value != pid: return True
        if expected:
            handle = kernel.OpenProcess(0x1000, False, owner.value)
            if not handle: return True
            name, size = ctypes.create_unicode_buffer(32768), W.DWORD(32768)
            try:
                if not kernel.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(size)) or name.value.casefold() != expected: return True
            finally: kernel.CloseHandle(handle)
        rect = W.RECT(); user.GetWindowRect(hwnd, ctypes.byref(rect))
        width, height = rect.right-rect.left, rect.bottom-rect.top
        if user.IsWindowVisible(hwnd) and not user.IsIconic(hwnd) and 50 <= width <= 4096 and 30 <= height <= 2160:
            found.append((width*height, hwnd, owner.value, width, height))
        return True
    callback = callback_type(visit)
    user.EnumWindows(callback, 0)
    if not found: raise RuntimeError('No visible non-minimized window belongs to this target process; no full-desktop fallback')
    _, hwnd, owner, width, height = max(found)
    dc = user.GetDC(hwnd); memory = gdi.CreateCompatibleDC(dc); bitmap = gdi.CreateCompatibleBitmap(dc, width, height)
    previous = gdi.SelectObject(memory, bitmap)
    try:
        if not user.PrintWindow(hwnd, memory, 2): raise RuntimeError('PrintWindow failed')
        gdi.SelectObject(memory, previous)
        class Header(ctypes.Structure):
            _fields_ = [('size',W.DWORD),('width',ctypes.c_long),('height',ctypes.c_long),('planes',W.WORD),('bits',W.WORD),('compression',W.DWORD),('bytes',W.DWORD),('x',ctypes.c_long),('y',ctypes.c_long),('colors',W.DWORD),('important',W.DWORD)]
        header = Header(40, width, -height, 1, 32, 0, 0, 0, 0, 0, 0)
        raw = ctypes.create_string_buffer(width*height*4)
        if gdi.GetDIBits(memory, bitmap, 0, height, raw, ctypes.byref(header), 0) != height: raise RuntimeError('GetDIBits failed')
        image = Image.frombytes('RGB', (width,height), raw.raw, 'raw', 'BGRX')
        if max(ImageStat.Stat(image).var) < 0.5: raise RuntimeError('Target window returned a blank frame')
        Path(output).parent.mkdir(parents=True, exist_ok=True); image.save(output, 'PNG')
    finally:
        gdi.SelectObject(memory, previous); gdi.DeleteObject(bitmap); gdi.DeleteDC(memory); user.ReleaseDC(hwnd, dc)
    return {'process_id': owner, 'window_handle': int(hwnd), 'width': width, 'height': height,
            'source': 'Actual Windows PrintWindow target process %d, HWND %s; no foreground switch' % (owner, int(hwnd))}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output',required=True); parser.add_argument('--pid',type=int); parser.add_argument('--executable')
    args = parser.parse_args()
    try: print(json.dumps(native_capture(args.output,args.pid,args.executable)))
    except Exception as exc: print(str(exc),file=sys.stderr); sys.exit(1)
