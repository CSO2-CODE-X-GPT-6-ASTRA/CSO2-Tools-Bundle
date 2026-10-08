# -*- coding: utf-8 -*-
"""CSO2 Local Master Server: launcher, server panel and restoration in one file.

Requires Windows, Python 3.10+ with Tk, and the adjacent dependency folder.
Embedded modules are loaded in memory; resources and new local settings stay
inside Dependencies 外部依赖. No existing accounts or logs are distributed.
"""
from pathlib import Path
import importlib.abc
import importlib.util
import sys

APP_ID = 'cso2-local-master-server'
APP_VERSION = '1.0.0'
UPDATE_REPOSITORY_ID = 1410625177
UPDATE_PROTOCOL = 3
UPDATE_TAG_PREFIX = 'host-tool-v'
UPDATE_COMPONENT_DIRS = ('Dependencies 外部依赖',)
UPDATE_STARTUP_TICKET = None
UPDATE_SKIP_ONCE = False
BUNDLE_ENTRY = Path(__file__).resolve()
DEPENDENCY_ROOT = BUNDLE_ENTRY.parent / 'Dependencies 外部依赖'
MODULE_SOURCES = {}

# --- cheat_settings ---
MODULE_SOURCES['cheat_settings'] = r'''"""Persist local sv_cheats and apply through the validated listen-server queue.

The login/lobby server is not Source's gameplay server. The actual ConVar lives
in the local game's engine.dll. No files in the game are patched here.
"""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

BASE=Path(__file__).resolve().parent


def _configured_game(cfg):
    value = cfg.get('game_root', '')
    if not value:
        raise RuntimeError('请先在本地启动器选择游戏目录')
    path = Path(value).expanduser()
    return (path if path.is_absolute() else BASE / path).resolve()


def atomic_json(path,value):
    temp=None
    try:
        with tempfile.NamedTemporaryFile('w',encoding='utf-8',dir=path.parent,prefix='.'+path.stem+'-',suffix='.tmp',delete=False) as f:
            temp=Path(f.name);json.dump(value,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(temp,path);temp=None
    finally:
        if temp:temp.unlink(missing_ok=True)

def save_enabled(enabled,expected_game=None,start=True):
    if type(enabled) is not bool:raise ValueError('作弊开关必须为 true 或 false')
    path=BASE/'local_config.json';cfg=json.loads(path.read_text(encoding='utf-8'))
    if expected_game is not None and _configured_game(cfg)!=Path(expected_game).resolve():raise RuntimeError('本地服务器配置的客户端与当前游戏不同，未更改')
    cfg.setdefault('rules',{})['sv_cheats']=enabled;atomic_json(path,cfg)
    running=False
    if start:
        try:
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f'http://127.0.0.1:{int(cfg["control_port"])}/health',timeout=1) as response:status=json.load(response)
            if status.get('instance')==cfg.get('instance') and status.get('ready') and Path(status.get('base','')).resolve()==BASE.resolve():
                start_monitor(status['supervisor_pid']);running=True
        except (OSError,ValueError,KeyError):pass
    return {'enabled':enabled,'monitor_requested':running}

def start_monitor(owner_pid):
    owner_pid=int(owner_pid)
    if owner_pid<=0:raise ValueError('服务器进程号无效')
    python=Path(sys.executable);windowless=python.with_name('pythonw.exe')
    if windowless.exists():python=windowless
    logs=BASE/'logs';logs.mkdir(exist_ok=True)
    with (logs/'sv_cheats.log').open('ab') as out:
        subprocess.Popen([str(python),str(BUNDLE_ENTRY),'--cheats-worker',str(owner_pid)],cwd=BASE,
                         stdin=subprocess.DEVNULL,stdout=out,stderr=out,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))

def status_message(state,health,config,base=BASE,now=None):
    """Do not present a dead monitor's old result as the current game state."""
    desired=config.get('rules',{}).get('sv_cheats')
    if type(desired) is not bool:return '未指定作弊设置，保持游戏原值。'
    if not health or not health.get('ready') or Path(health.get('base','')).resolve()!=Path(base).resolve():
        return '作弊设置已保存；等待本目录的服务器启动。'
    stamp=state.get('updated_at',0)
    if (state.get('owner_pid')!=health.get('supervisor_pid') or
        not isinstance(stamp,(int,float)) or not 0<=(time.time() if now is None else now)-stamp<=15):
        return '作弊设置已保存；等待监控器确认（旧状态已过期）。'
    if state.get('state')=='applied' and (state.get('actual') is not desired or state.get('enabled') is not desired):
        return '作弊设置已保存；等待游戏应用最新选择。'
    return '作弊状态：'+str(state.get('message','等待游戏确认'))

def watch(owner_pid):
    from host_native import Backend
    k=C.WinDLL('kernel32',use_last_error=True)
    k.CreateMutexW.argtypes=[C.c_void_p,W.BOOL,W.LPCWSTR];k.CreateMutexW.restype=W.HANDLE
    k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
    k.GetExitCodeProcess.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];k.GetExitCodeProcess.restype=W.BOOL
    k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.WaitForSingleObject.restype=W.DWORD
    k.ReleaseMutex.argtypes=[W.HANDLE];k.ReleaseMutex.restype=W.BOOL
    k.CloseHandle.argtypes=[W.HANDLE]
    mutex=k.CreateMutexW(None,False,'Local\\CSO2_sv_cheats_'+hashlib.sha256(str(BASE.resolve()).encode()).hexdigest()[:20])
    if not mutex:raise C.WinError(C.get_last_error())
    owner=k.OpenProcess(0x1000,False,owner_pid)
    if not owner:k.CloseHandle(mutex);return
    acquired=False
    # A newly started supervisor must outlive an old monitor releasing its lock.
    # A duplicate for the same owner exits; restart handoff waits at most 5s.
    for _ in range(25):
        result=k.WaitForSingleObject(mutex,200)
        if result in (0,0x80):acquired=True;break
        if result==0xffffffff:break
        try:
            old=json.loads((BASE/'sv_cheats_state.json').read_text(encoding='utf-8'))
            if old.get('owner_pid')==owner_pid:break
        except (OSError,ValueError):pass
        code=W.DWORD()
        if not k.GetExitCodeProcess(owner,C.byref(code)) or code.value!=259:break
    if not acquired:k.CloseHandle(owner);k.CloseHandle(mutex);return
    backend=Backend();last_state=None;last_report=0.;last_send=0.;last_connect=0.
    def report(state):
        nonlocal last_state,last_report
        if state!=last_state or time.monotonic()-last_report>=5:
            atomic_json(BASE/'sv_cheats_state.json',dict(state,owner_pid=owner_pid,updated_at=time.time()));last_state=state;last_report=time.monotonic()
    try:
        while True:
            code=W.DWORD()
            if not k.GetExitCodeProcess(owner,C.byref(code)) or code.value!=259:break
            try:
                cfg=json.loads((BASE/'local_config.json').read_text(encoding='utf-8'))
                desired=cfg.get('rules',{}).get('sv_cheats')
                if type(desired) is not bool:
                    report({'state':'unconfigured','message':'未指定作弊设置，保持游戏原值'})
                    time.sleep(1);continue
                if not backend.mem or not backend.mem.alive():
                    backend.close()
                    if time.monotonic()-last_connect<3:time.sleep(1);continue
                    last_connect=time.monotonic();backend.connect(_configured_game(cfg))
                if backend.game.resolve()!=_configured_game(cfg):raise RuntimeError('当前游戏与本地服务器配置路径不符')
                backend.snapshot();backend.require('cheats');actual=backend.cheats_value()
                if actual==desired:report({'state':'applied','enabled':desired,'actual':actual,'message':'游戏 sv_cheats 已'+('开启' if desired else '关闭')})
                else:
                    if time.monotonic()-last_send>=2:
                        backend.set_cheats(desired);last_send=time.monotonic()
                    report({'state':'pending','enabled':desired,'actual':actual,'message':'设置已发送，等待游戏确认'})
                if backend.queue:backend.queue.poll()
            except Exception as ex:
                backend.invalidate();report({'state':'waiting','message':str(ex)})
            time.sleep(1)
    finally:
        try:backend.close()
        finally:k.ReleaseMutex(mutex);k.CloseHandle(owner);k.CloseHandle(mutex)

if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--watch':watch(int(sys.argv[2]))
'''

# --- client_cache_patch ---
MODULE_SOURCES['client_cache_patch'] = r'''"""Install a verified, reversible client DLL patch while the DLL is unloaded."""
from contextlib import contextmanager
import ctypes as C
from ctypes import wintypes as W
import hashlib,json,os
from pathlib import Path
import tempfile

BASE=Path(__file__).resolve().parent
ORIGINAL='53fec05d61c1bdd019a337c18f0e720c14e8644fa128a34a13d200cbcd20f946'
PATCHED='e35518231a59b990909cca48d68b09ea0b07b303f0a6faf0d600c81b969d386d'
VERSION='2026.09.20-vvd-alloc1'


def _hash(data):return hashlib.sha256(data).hexdigest()


def _atomic(path,data):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix=path.name+'.',suffix='.tmp',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)


def _json(path,value):_atomic(path,json.dumps(value,ensure_ascii=False,indent=2).encode('utf-8'))


def _mapped_pids(target):
    from host_native import snapshot_entries,PROCESSENTRY32W,modules
    wanted=target.resolve();found=[]
    for process in snapshot_entries(2,0,PROCESSENTRY32W,'Process32FirstW','Process32NextW'):
        if process.th32ProcessID<=4:continue
        try:
            mod=modules(process.th32ProcessID).get('datacache.dll')
            if mod and mod[2].resolve()==wanted:found.append(process.th32ProcessID)
        except OSError:pass  # The exclusive writable-file guard is authoritative.
    return found


@contextmanager
def _exclusive_image(path):
    """Verify writable exclusive access while validating and backing up the DLL.

    Windows refuses writable access to a mapped executable image. No writes to
    the old image are performed; replacement is a separate, fully staged file.
    The handle must close before Windows permits destination replacement.
    """
    k=C.WinDLL('kernel32',use_last_error=True)
    k.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
    k.CreateFileW.restype=W.HANDLE
    k.ReadFile.argtypes=[W.HANDLE,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.c_void_p];k.ReadFile.restype=W.BOOL
    k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
    handle=k.CreateFileW(str(path),0xc0000000,4,None,3,0x80,None)
    if handle==C.c_void_p(-1).value:raise C.WinError(C.get_last_error())
    try:
        chunks=[]
        while True:
            buf=C.create_string_buffer(65536);n=W.DWORD()
            if not k.ReadFile(handle,buf,len(buf),C.byref(n),None):raise C.WinError(C.get_last_error())
            if not n.value:break
            chunks.append(buf.raw[:n.value])
        yield b''.join(chunks)
    finally:k.CloseHandle(handle)


def apply_pending(game_root, restore=None):
    target=Path(game_root).resolve()/'Bin/datacache.dll'
    flag=BASE/'client_cache_patch_enabled.json'
    enabled=True
    if flag.exists():
        option=json.loads(flag.read_text(encoding='utf-8'))
        if type(option.get('enabled')) is not bool:raise RuntimeError('客户端补丁开关记录无效。')
        enabled=option['enabled']
    if restore is not None:
        enabled=not restore;_json(flag,{'enabled':enabled})
    desired=PATCHED if enabled else ORIGINAL
    def finish(status,**kwargs):
        result={'version':VERSION,'status':status,'enabled':enabled,'target':str(target),**kwargs}
        _json(BASE/'client_cache_patch_status.json',result)
        return result
    if not target.is_file():return finish('unsupported',reason='该目录没有 datacache.dll，未改客户端。')
    current=_hash(target.read_bytes())
    if current==desired:return finish('applied' if enabled else 'restored',sha256=current)
    if current not in (ORIGINAL,PATCHED):
        return finish('unsupported',reason='客户端版本不匹配，未覆盖其他版本。',sha256=current)
    active=_mapped_pids(target)
    if active:return finish('pending',reason='游戏仍在使用原文件；退出后下次启动前自动安装。',pids=active)
    source=BASE/'client_patches/vvd_alloc1'/('datacache.patched.dll' if enabled else 'datacache.original.dll')
    payload=source.read_bytes()
    if _hash(payload)!=desired:raise RuntimeError('客户端补丁文件校验失败，未修改游戏。')
    try:
        with _exclusive_image(target) as old:
            if _hash(old)!=current:raise RuntimeError('客户端文件在检查期间发生变化，未覆盖。')
            backup=BASE/'client_patches/vvd_alloc1/backups'/('datacache.'+current+'.dll')
            if backup.exists():
                if _hash(backup.read_bytes())!=current:raise RuntimeError('客户端补丁备份校验失败。')
            else:_atomic(backup,old)
        # The final replacement also fails if the image becomes mapped here.
        # Do not delete/rename the original out of the way to bypass that check.
        if _hash(target.read_bytes())!=current:
            raise RuntimeError('客户端文件在备份后发生变化，未覆盖。')
        _atomic(target,payload)
    except OSError as exc:
        return finish('pending',reason='客户端文件尚被占用或不可写，保留待安装状态。',error=str(exc))
    if _hash(target.read_bytes())!=desired:raise RuntimeError('客户端补丁写入后校验失败。')
    return finish('applied' if enabled else 'restored',sha256=desired,backup=str(backup))


def before_launch(game_root):
    result=apply_pending(game_root)
    if result['status']=='pending':
        raise RuntimeError('客户端模型加载补丁等待安装：'+result['reason'])
    return result


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--game-root');parser.add_argument('--restore',action='store_true')
    parser.add_argument('--enable',action='store_true');args=parser.parse_args()
    from game_paths import load_local_config
    root=args.game_root or load_local_config(BASE/'local_config.json')['game_root']
    restore=True if args.restore else False if args.enable else None
    print(json.dumps(apply_pending(root,restore),ensure_ascii=False,indent=2))
'''

# --- client_diagnostics ---
MODULE_SOURCES['client_diagnostics'] = r'''"""Independent, read-only client crash recorder. No input or graphics changes."""
import ctypes as C
from ctypes import wintypes as W
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

BASE=Path(__file__).resolve().parent


class Module(C.Structure):
    _fields_=[('size',W.DWORD),('id',W.DWORD),('pid',W.DWORD),('global_count',W.DWORD),
              ('process_count',W.DWORD),('base',C.c_void_p),('length',W.DWORD),('handle',W.HMODULE),
              ('name',W.WCHAR*256),('path',W.WCHAR*260)]


class Counters(C.Structure):
    _fields_=[('cb',W.DWORD),('faults',W.DWORD)]+[(n,C.c_size_t) for n in
        ('peak_working','working','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile','private')]


class Region(C.Structure):
    _fields_=[('base',C.c_void_p),('allocation',C.c_void_p),('allocation_protection',W.DWORD),
              ('partition',W.WORD),('size',C.c_size_t),('state',W.DWORD),('protection',W.DWORD),('type',W.DWORD)]


def kernel():
    k=C.WinDLL('kernel32',use_last_error=True)
    signatures={
        'OpenProcess':(W.HANDLE,[W.DWORD,W.BOOL,W.DWORD]),
        'CloseHandle':(W.BOOL,[W.HANDLE]),
        'ReadProcessMemory':(W.BOOL,[W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]),
        'GetExitCodeProcess':(W.BOOL,[W.HANDLE,C.POINTER(W.DWORD)]),
        'CreateToolhelp32Snapshot':(W.HANDLE,[W.DWORD,W.DWORD]),
        'Module32FirstW':(W.BOOL,[W.HANDLE,C.POINTER(Module)]),
        'Module32NextW':(W.BOOL,[W.HANDLE,C.POINTER(Module)]),
        'VirtualQueryEx':(C.c_size_t,[W.HANDLE,C.c_void_p,C.POINTER(Region),C.c_size_t]),
        'K32GetProcessMemoryInfo':(W.BOOL,[W.HANDLE,C.POINTER(Counters),W.DWORD]),
        'CreateMutexW':(W.HANDLE,[C.c_void_p,W.BOOL,W.LPCWSTR]),
    }
    for name,(restype,argtypes) in signatures.items():
        fn=getattr(k,name);fn.restype=restype;fn.argtypes=argtypes
    return k


def modules(k,pid):
    handle=k.CreateToolhelp32Snapshot(0x18,pid)
    if handle==C.c_void_p(-1).value:return {}
    result={}
    try:
        row=Module();row.size=C.sizeof(row);ok=k.Module32FirstW(handle,C.byref(row))
        while ok:
            name=row.name.lower()
            # ReShade and system d3d9 can both be loaded under the same basename.
            # Preserve both paths so diagnostics don't falsely report its absence.
            if name in result:name=name+'#'+str(row.base)
            result[name]=(row.base,Path(row.path))
            ok=k.Module32NextW(handle,C.byref(row))
    finally:k.CloseHandle(handle)
    return result


def memory(k,handle):
    c=Counters();c.cb=C.sizeof(c)
    if not k.K32GetProcessMemoryInfo(handle,C.byref(c),c.cb):raise C.WinError(C.get_last_error())
    address=free=largest=0
    while address<0x100000000:
        r=Region()
        if not k.VirtualQueryEx(handle,address,C.byref(r),C.sizeof(r)) or not r.size:break
        size=min(r.size,0x100000000-address)
        if r.state==0x10000:free+=size;largest=max(largest,size)
        address=(r.base or 0)+r.size
    return dict(private_mb=round(c.private/1048576,1),working_mb=round(c.working/1048576,1),
                address_free_mb=round(free/1048576,1),largest_free_mb=round(largest/1048576,1))


def config_changes(before,after):
    if before is None:return []
    return [{'offset':i,'before':a,'after':b} for i,(a,b) in enumerate(zip(before,after)) if a!=b]


def record(pid,game_root):
    record_started=time.time()
    game_root=Path(game_root).resolve();k=kernel()
    mutex=k.CreateMutexW(None,False,'Local\\CSO2ReadOnlyDiagnostics_'+str(pid))
    if C.get_last_error()==183:
        k.CloseHandle(mutex);return
    handle=k.OpenProcess(0x410,False,pid)
    if not handle:
        k.CloseHandle(mutex);return
    out=BASE/'logs/client_diagnostics'/(datetime.datetime.now().strftime('%Y%m%d_%H%M%S')+'_'+str(pid))
    out.mkdir(parents=True,exist_ok=True)
    def read(address,size):
        data=C.create_string_buffer(size);n=C.c_size_t()
        if not k.ReadProcessMemory(handle,address,data,size,C.byref(n)) or n.value!=size:raise OSError('Memory unavailable')
        return data.raw
    previous=None;previous_options=None;last_memory=-100.;verified=False;seen_modules=False;mat=eng=client=None
    from memory_pressure import classify,describe,fatal_diagnosis
    previous_pressure=None
    summary={'pid':pid,'read_only':True,'graphics_changed':False,'samples':0,'config_changes':0}
    try:
        with (out/'events.jsonl').open('w',encoding='utf-8',buffering=1) as log:
            def event(kind,**data):
                log.write(json.dumps(dict(time=datetime.datetime.now().astimezone().isoformat(),event=kind,**data),ensure_ascii=False)+'\n')
            while True:
                code=W.DWORD()
                if not k.GetExitCodeProcess(handle,C.byref(code)):break
                if code.value!=259:
                    summary['exit_code']=code.value;event('exit',code=code.value);break
                now=time.monotonic()
                if now-last_memory>=5:
                    data=memory(k,handle);summary['last_memory']=data;summary['samples']+=1
                    summary['peak_private_mb']=max(summary.get('peak_private_mb',0),data['private_mb'])
                    event('memory',**data);last_memory=now
                    level=classify(data)
                    summary['last_pressure']=level
                    if level!=previous_pressure:
                        event('memory_pressure',level=level,message=describe(data))
                        previous_pressure=level
                    if not seen_modules:
                        mods=modules(k,pid)
                        if 'engine.dll' in mods and 'materialsystem.dll' in mods:
                            expected={
                                'engine.dll':'3a348976bf5e1d814d9fa6e5ad857298f7fb900094b4f5b84b60176656f22f5c',
                                'materialsystem.dll':MATERIAL_HASH,
                            }
                            verified=all(p.parent.resolve()==game_root/'Bin' and hashlib.sha256(p.read_bytes()).hexdigest()==expected[n] for n,(a,p) in mods.items() if n in expected)
                            eng=mods['engine.dll'][0];mat=mods['materialsystem.dll'][0];seen_modules=True
                            if 'client.dll' in mods:
                                cb,cp=mods['client.dll']
                                if cp.parent.resolve()==game_root/'Bin' and hashlib.sha256(cp.read_bytes()).hexdigest()=='93fdee4c4d09d0fd79468de3384abc3a92a757864fd37d4ad6de25d8a371bc06':client=cb
                            event('modules',verified=verified,paths={n:str(p) for n,(a,p) in mods.items() if n in expected or n.startswith('d3d9.dll')})
                if verified:
                    try:
                        current=read(mat+0x162ad0,132)
                        if current!=previous:
                            summary['config_changes']+=1
                            event('material_config',hex=current.hex(),changes=config_changes(previous,current),signon=struct.unpack('<i',read(eng+0x8d22c4,4))[0])
                            previous=current
                        if client:
                            options=read(client+0x1cdd598,248)
                            opened=read(client+0x1cddb34,1)[0]
                            stamp=(options,opened)
                            if stamp!=previous_options:
                                event('options_state',opened=opened,applied=options[:80].hex(),pending=options[88:168].hex(),loaded=options[168:248].hex())
                                previous_options=stamp
                    except OSError:pass
                time.sleep(.2)
    except Exception as exc:summary['error']=type(exc).__name__+': '+str(exc)
    finally:
        k.CloseHandle(handle);k.CloseHandle(mutex)
        # Copy immediately on exit, before a later launch overwrites these logs.
        for name in ('cso2_report_log.txt','timestamped.log','Error.log'):
            path=game_root/'Bin'/name
            if path.is_file():
                try:shutil.copy2(path,out/name)
                except OSError:pass
        try:
            archived=out/'cso2_report_log.txt'
            if archived.is_file() and archived.stat().st_mtime>=record_started:
                reason=fatal_diagnosis(archived.read_text(encoding='utf-8',errors='replace'))
                if reason:summary['fatal_diagnosis']=reason
        except OSError:pass
        (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')


def start(pid,game_root):
    if not pid:return
    python=Path(sys.executable).with_name('pythonw.exe')
    if not python.exists():python=Path(sys.executable)
    try:
        subprocess.Popen([str(python),str(BUNDLE_ENTRY),'--diagnostics-worker',str(int(pid)),str(game_root)],
                         stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=0x08000000)
        return True
    except OSError:return False


MATERIAL_HASH='7ae6f5a484ca34513621b056cf7a2ac66de36cbda68d5c86c78da76d5941e02e'

if __name__=='__main__':record(int(sys.argv[1]),sys.argv[2])
'''

# --- display_settings ---
MODULE_SOURCES['display_settings'] = r'''"""Shared validation for preset/custom game launch dimensions."""
PRESETS = ('1024 × 768','1280 × 720','1280 × 800','1366 × 768','1600 × 900',
           '1920 × 1080','1920 × 1200','2560 × 1440','3840 × 2160','自定义')


def validate(width, height, fullscreen=False):
    try:
        width=int(str(width).strip());height=int(str(height).strip())
    except (ValueError,TypeError):
        raise ValueError('宽度和高度必须是整数。') from None
    if not 640<=width<=7680 or not 480<=height<=4320:
        raise ValueError('宽度范围 640–7680，高度范围 480–4320。')
    return {'width':width,'height':height,'windowed':not bool(fullscreen),'borderless':False}


def from_config(cfg):
    return validate(cfg.get('width',1280),cfg.get('height',720),not cfg.get('windowed',True))


def arguments(cfg):
    value=from_config(cfg)
    mode=['-windowed','-startwindowed'] if value['windowed'] else ['-fullscreen']
    return mode+['-width',str(value['width']),'-height',str(value['height'])]


def registry_values(cfg):
    value=from_config(cfg)
    return {'ScreenWidth':value['width'],'ScreenHeight':value['height'],
            'ScreenWindowed':int(value['windowed']),'ScreenBorderless':0}
'''

# --- game_paths ---
MODULE_SOURCES['game_paths'] = r'''"""Cancellable folder discovery; no registry changes or process launches."""
from __future__ import annotations
from collections import deque
import os
from pathlib import Path
import stat
import threading



def resolve_config_paths(config, base):
    """Anchor saved relative paths to the package, never to the working directory."""
    result = dict(config)
    value = result.get('game_root', '')
    if value:
        path = Path(value).expanduser()
        result['game_root'] = str((path if path.is_absolute() else Path(base) / path).resolve())
    return result


def load_local_config(path=None):
    import json
    path = Path(path) if path is not None else Path(__file__).resolve().parent / 'local_config.json'
    return resolve_config_paths(json.loads(path.read_text(encoding='utf-8')), path.resolve().parent)


def portable_local_config(config, path):
    """Persist same-volume selections relatively; preserve explicit other-volume choices."""
    path = Path(path).resolve()
    result = dict(config)
    value = result.get('game_root', '')
    if value:
        selected = Path(resolve_config_paths(result, path.parent)['game_root'])
        try: result['game_root'] = Path(os.path.relpath(selected, path.parent)).as_posix()
        except ValueError: result['game_root'] = str(selected)
    return result


REQUIRED = ('Bin/CounterStrikeOnline2.exe', 'Bin/client.dll', 'Bin/engine.dll', 'Bin/server.dll')


def validate_game(path):
    if path is None or not str(path).strip():
        return None
    root = Path(path).expanduser().resolve()
    if root.name.lower() == 'bin':
        root = root.parent
    for name in REQUIRED:
        try:
            with (root / name).open('rb') as f:
                if f.read(2) != b'MZ':
                    return None
        except OSError:
            return None
    if not (root / 'Data').is_dir():
        return None
    return root


def scan_games(folder, cancel=None, progress=None):
    cancel = cancel or threading.Event()
    selected = Path(folder).expanduser().resolve()
    if not selected.is_dir():
        raise ValueError('请选择存在的文件夹。')
    direct = validate_game(selected)
    if direct:
        return {'paths': [str(direct)], 'visited': 1, 'skipped': 0, 'cancelled': False}
    pending = deque([selected]); found = {}; visited = skipped = 0
    while pending and not cancel.is_set():
        current = pending.popleft(); visited += 1
        game = validate_game(current)
        if game:
            found[str(game).casefold()] = str(game)
            continue  # A validated client's resource tree cannot contain another install.
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if cancel.is_set():
                        break
                    if entry.name.casefold() in {'.git', '$recycle.bin', 'system volume information', '__pycache__'}:
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        attr = getattr(entry.stat(follow_symlinks=False), 'st_file_attributes', 0)
                        if not attr & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                            pending.append(Path(entry.path))
        except OSError:
            skipped += 1
        if progress and visited % 50 == 0:
            progress(visited, len(found))
    return {'paths': sorted(found.values(), key=str.casefold), 'visited': visited,
            'skipped': skipped, 'cancelled': cancel.is_set()}
'''

# --- host_data ---
MODULE_SOURCES['host_data'] = r'''# Only the command/weapon database is compressed JSON; no code is encoded.
import base64, json, zlib
DATA = json.loads(zlib.decompress(base64.b64decode('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')))
'''

# --- host_native ---
MODULE_SOURCES['host_native'] = r'''"""CSO2 host backend, pinned to the inspected 32-bit game build.

No game operations run at import. The UI worker owns every game handle.
"""
from __future__ import annotations
import base64
import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import struct
import tempfile
import threading
import time
from runtime_compat import (choose_candidate,game_root,verify_family,resolve_module,native_loopback,command_entry,field_check,probe_result)
from host_specs import COMPAT_SPECS
from host_data import DATA

FINGERPRINTS = {
    'client.dll':'93fdee4c4d09d0fd79468de3384abc3a92a757864fd37d4ad6de25d8a371bc06',
    'engine.dll':'3a348976bf5e1d814d9fa6e5ad857298f7fb900094b4f5b84b60176656f22f5c',
    'server.dll':'fd566dd57795ea6839fece87cd59e0175da364d1774ec6123a5f288b6e77fec2',
    'counterstrikeonline2.exe':'4b054288805fd997b0493eac119175da04588c4b4ef22db49c7523cf8567553a',
}


def _local_package_base(entry=None, environ=None):
    """Find only the adjacent local package, or an explicit absolute override."""
    import os
    folder = Path(entry or __file__).resolve().parent
    env = os.environ if environ is None else environ
    override = env.get('CSO2_LOCAL_BASE', '').strip()
    if override:
        value = Path(override).expanduser()
        if not value.is_absolute():
            raise ValueError('CSO2_LOCAL_BASE must be an absolute directory')
        return value.resolve()
    candidates = (folder / 'CSO2本地玩', folder)
    return next((p for p in candidates if (p / 'local_config.json').is_file()), candidates[0])


class NotReady(RuntimeError): pass

class PROCESSENTRY32W(C.Structure):
    _fields_=[('dwSize',W.DWORD),('cntUsage',W.DWORD),('th32ProcessID',W.DWORD),('th32DefaultHeapID',C.c_size_t),('th32ModuleID',W.DWORD),('cntThreads',W.DWORD),('th32ParentProcessID',W.DWORD),('pcPriClassBase',W.LONG),('dwFlags',W.DWORD),('szExeFile',W.WCHAR*260)]

class MODULEENTRY32W(C.Structure):
    _fields_=[('dwSize',W.DWORD),('th32ModuleID',W.DWORD),('th32ProcessID',W.DWORD),('GlblcntUsage',W.DWORD),('ProccntUsage',W.DWORD),('modBaseAddr',C.c_void_p),('modBaseSize',W.DWORD),('hModule',W.HMODULE),('szModule',W.WCHAR*256),('szExePath',W.WCHAR*260)]

def snapshot_entries(flags,pid,kind,first,next_):
    k=C.WinDLL('kernel32',use_last_error=True)
    k.CreateToolhelp32Snapshot.argtypes=[W.DWORD,W.DWORD];k.CreateToolhelp32Snapshot.restype=W.HANDLE
    k.CloseHandle.argtypes=[W.HANDLE]
    f,n=getattr(k,first),getattr(k,next_)
    for fn in (f,n):fn.argtypes=[W.HANDLE,C.POINTER(kind)];fn.restype=W.BOOL
    handle=k.CreateToolhelp32Snapshot(flags,pid)
    if handle==C.c_void_p(-1).value:raise C.WinError(C.get_last_error())
    try:
        row=kind();row.dwSize=C.sizeof(row);ok=f(handle,C.byref(row))
        while ok:
            yield kind.from_buffer_copy(row)
            ok=n(handle,C.byref(row))
    finally:k.CloseHandle(handle)

def game_pids():
    return [e.th32ProcessID for e in snapshot_entries(2,0,PROCESSENTRY32W,'Process32FirstW','Process32NextW') if e.th32ProcessID>4 and e.th32ProcessID!=os.getpid()]

def modules(pid):
    return {e.szModule.lower():(e.modBaseAddr,e.modBaseSize,Path(e.szExePath)) for e in snapshot_entries(0x18,pid,MODULEENTRY32W,'Module32FirstW','Module32NextW')}

class WinMemory:
    def __init__(self,pid):
        self.pid=pid;self.handle=None;self.write_handle=None
        self.k=C.WinDLL('kernel32',use_last_error=True)
        signatures={
            'OpenProcess':(W.HANDLE,[W.DWORD,W.BOOL,W.DWORD]),
            'CloseHandle':(W.BOOL,[W.HANDLE]),
            'ReadProcessMemory':(W.BOOL,[W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]),
            'WriteProcessMemory':(W.BOOL,[W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]),
            'GetExitCodeProcess':(W.BOOL,[W.HANDLE,C.POINTER(W.DWORD)]),
        }
        for name,(ret,args) in signatures.items():
            fn=getattr(self.k,name);fn.restype=ret;fn.argtypes=args
        self.handle=self.k.OpenProcess(0x410,False,pid)
        if not self.handle:raise OSError(f'无法读取游戏（Windows 错误 {C.get_last_error()}；请检查两边运行权限）')
    def read(self,address,size):
        if not 0x10000<=address<0xffff0000 or not 0<size<=4*1024*1024:raise RuntimeError('读取地址或长度异常')
        buf=C.create_string_buffer(size);n=C.c_size_t()
        if not self.k.ReadProcessMemory(self.handle,address,buf,size,C.byref(n)) or n.value!=size:raise NotReady(f'游戏数据正在变化：0x{address:08X}')
        return buf.raw
    def u32(self,a):return struct.unpack('<I',self.read(a,4))[0]
    def i32(self,a):return struct.unpack('<i',self.read(a,4))[0]
    def string(self,a,size=128):
        value=self.read(a,size).split(b'\0')[0]
        for enc in ('utf-8','gb18030'):
            try:return value.decode(enc)
            except UnicodeDecodeError:pass
        return value.decode('utf-8',errors='replace')
    def alive(self):
        code=W.DWORD()
        return bool(self.handle and self.k.GetExitCodeProcess(self.handle,C.byref(code))) and code.value==259
    def write(self,address,data):
        if not 0x10000<=address<0xffff0000 or not 0<len(data)<=4096:raise RuntimeError('写入地址或长度异常')
        if not self.write_handle:
            self.write_handle=self.k.OpenProcess(0x28,False,self.pid)
            if not self.write_handle:raise OSError(f'无法写入游戏（Windows 错误 {C.get_last_error()}）')
        n=C.c_size_t();buf=C.create_string_buffer(data)
        if not self.k.WriteProcessMemory(self.write_handle,address,buf,len(data),C.byref(n)) or n.value!=len(data):raise OSError('游戏数据写入失败')
    def close(self):
        for h in (self.write_handle,self.handle):
            if h:self.k.CloseHandle(h)
        self.write_handle=self.handle=None

def command_bytes(text):
    text=str(text).strip()
    if not text or any(ord(ch)<32 or ord(ch)==127 for ch in text):raise ValueError('指令不能为空，也不能包含换行或控制字符')
    data=(text+'\n').encode('utf-8')+b'\0'
    if len(data)>512:raise ValueError('指令过长，UTF-8 编码后最多 510 字节')
    return data

def console_segments(text):
    """Tokenize the supported single-line Source console syntax, including quotes."""
    result=[];tokens=[];token=[];quoted=False;started=False
    for ch in str(text):
        if ch=='"':quoted=not quoted;started=True
        elif not quoted and (ch.isspace() or ch==';'):
            if started:tokens.append(''.join(token));token=[];started=False
            if ch==';' and tokens:result.append(tokens);tokens=[]
        else:token.append(ch);started=True
    if quoted:raise ValueError('指令双引号未闭合')
    if started:tokens.append(''.join(token))
    if tokens:result.append(tokens)
    return result

def chat_command(text,team=False):
    text=text.strip()
    if not text:raise ValueError('请先输入喊话内容')
    # The Source tokenizer does not give us a reliable escaped quote syntax.
    if any(ch in text for ch in ('"',';','\n','\r','\0','\\')) or any(ord(ch)<32 for ch in text):
        raise ValueError('喊话请使用单行文字，不要包含双引号、分号或反斜杠')
    if len(text.encode('utf-8'))>180:raise ValueError('喊话最多 180 字节（约 60 个汉字）')
    return ('say_team' if team else 'say')+' "'+text+'"'

class CommandQueue:
    """Call only the inspected thread-safe native ClientCmd queue (RET 4)."""
    def __init__(self,backend):
        m=backend.mem;e=backend.engine;c=backend.client
        interface=m.u32(c+0x1cdbb5c);vt=m.u32(interface);command=m.u32(vt+0x20)
        expected=(b'\x80\x3d'+struct.pack('<I',e+0x912b9d)+bytes.fromhex('007425a1')+
            struct.pack('<I',e+0x754b18)+bytes.fromhex('83c0023d000800007d1f8b542404b9630000006a64e87862efff83c404c204008b4c2404e8f95fefffc20400'))
        if command!=e+0x1830b0 or m.read(command,len(expected))!=expected:raise RuntimeError('游戏原生命令入口与已分析版本不符')
        self.command=command;self.handle=None;self.pending=None;self.k=m.k
        signatures={
            'VirtualAllocEx':(C.c_void_p,[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,W.DWORD]),
            'VirtualFreeEx':(W.BOOL,[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD]),
            'CreateRemoteThread':(W.HANDLE,[W.HANDLE,C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)]),
            'WaitForSingleObject':(W.DWORD,[W.HANDLE,W.DWORD]),
        }
        for name,(ret,args) in signatures.items():
            fn=getattr(self.k,name);fn.restype=ret;fn.argtypes=args
        self.handle=self.k.OpenProcess(0x043a,False,m.pid)
        if not self.handle:raise C.WinError(C.get_last_error())
    def poll(self,timeout=0):
        if self.pending is None:return True
        thread,address=self.pending;result=self.k.WaitForSingleObject(thread,timeout)
        if result==0:
            self.k.CloseHandle(thread);self.k.VirtualFreeEx(self.handle,address,0,0x8000);self.pending=None
            return True
        if result==0xffffffff:raise C.WinError(C.get_last_error())
        return False
    def send(self,text):
        data=command_bytes(text)
        if not self.poll(250):raise RuntimeError('上条命令仍在排队，请稍后重试')
        address=self.k.VirtualAllocEx(self.handle,None,len(data),0x3000,0x04)
        if not address:raise C.WinError(C.get_last_error())
        try:
            n=C.c_size_t();buf=C.create_string_buffer(data)
            if not self.k.WriteProcessMemory(self.handle,address,buf,len(data),C.byref(n)) or n.value!=len(data):raise C.WinError(C.get_last_error())
            thread=self.k.CreateRemoteThread(self.handle,None,0,self.command,address,0,None)
            if not thread:raise C.WinError(C.get_last_error())
        except Exception:
            self.k.VirtualFreeEx(self.handle,address,0,0x8000);raise
        self.pending=(thread,address)
    def close(self):
        try:self.poll(500)
        finally:
            # A running queue call still owns the string. Never free it early.
            if self.pending:self.k.CloseHandle(self.pending[0]);self.pending=None
            if self.handle:self.k.CloseHandle(self.handle);self.handle=None

@dataclass(frozen=True)
class PlayerKey:
    epoch:int
    map_name:str
    index:int
    address:int
    serial:int

@dataclass
class Player:
    key:PlayerKey
    name:str
    health:int
    maximum:int
    money:int
    team:int
    alive:bool
    local:bool=False

@dataclass
class MutationMachine:
    key:PlayerKey
    skill:int
    enabled:bool
    pending:bool

# Datamap and SendProp offsets were checked in the loaded server module.
FIELDS=(
    (0x9c01e8,'m_iHealth',0xf4,4),(0x9c01b4,'m_iMaxHealth',0xf0,4),(0x9c014c,'m_lifeState',0xf8,4),
    (0x9f4298,'m_iAccount',0x1c3c,4),(0xcadd40,'m_iMaxAccount',0x1c40,24),
    (0x9ddee8,'m_szNetname',0xed0,4),(0x9f4b84,'m_flHeadScale',0x6f0,4),(0x9f4bb8,'m_flBodyScale',0x6f4,4),
    (0x9bf3c8,'m_iClip1',0x54c,4),(0x9bf394,'m_iPrimaryAmmoType',0x53c,4),
    (0x9bef4c,'m_hMyWeapons',0x7ac,4),(0x9bef80,'m_hActiveWeapon',0x86c,4),
    (0xc7a1f8,'m_iAmmo',0x75c,24),(0x9f71b8,'m_iUserFlag',0x6e0,4),
)

class Backend:
    def __init__(self):
        self.mem=None;self.queue=None;self.mods={};self.server=0;self.epoch=0;self.map_name='';self.local_index=0;self.context=None;self.mutation_pending=None
        self.module_loader=modules;self.next_modules=0.;self.core_verified=False;self.server_reason='未连接';self.capabilities={}
        self.catalog={row['name'].casefold():row for row in DATA['catalog']}
    def connect(self,preferred=None):
        self.close();candidates=[]
        for pid in game_pids():
            try:mods=self.module_loader(pid)
            except OSError:continue
            if all(name in mods for name in ('client.dll','engine.dll')):candidates.append((pid,mods))
        pid,self.mods=choose_candidate(candidates,preferred or Path.cwd())
        self.client=self.mods['client.dll'][0];self.engine=self.mods['engine.dll'][0]
        self.game=game_root(self.mods['client.dll'][2]);self.mem=WinMemory(pid);self.epoch+=1
        try:
            self.verify_core();self.refresh_server(force=True);self.refresh_capabilities()
        except Exception:self.close();raise
        return pid
    def verify_file(self,name):return verify_family(self.mods[name],name)
    def verify_core(self):
        for name,spec in COMPAT_SPECS.items():
            required={key:anchors for key,anchors in spec['anchors'].items() if not key.startswith('netprop:') and key not in ('attack','attack2')}
            resolve_module(self.mem,self.mods[name],dict(spec,anchors=required))
        self.core_verified=True
    def refresh_server(self,force=False):
        now=time.monotonic()
        if not force and now<self.next_modules:return
        self.next_modules=now+.5
        current=self.module_loader(self.mem.pid)
        for name in ('client.dll','engine.dll'):
            if current.get(name)!=self.mods.get(name):raise NotReady('客户端模块已变化，请重新连接')
        self.verify_core()
        self.mods=current;self.server=0;self.server_reason='当前未加载本地服务器模块'
        if 'server.dll' in current:
            try:self.bind_server()
            except Exception as ex:self.server_reason=str(ex)
    def bind_server(self):
        self.verify_file('server.dll');self.server=self.mods['server.dll'][0];self.server_reason=''
    def local_connection(self):
        try:return native_loopback(self)
        except Exception as ex:raise NotReady(str(ex)) from ex
    def require_local(self):
        if not self.server:raise NotReady(self.server_reason)
        if not self.local_connection():raise NotReady('当前连接未确认为本地房主')
    def check_fields(self,names):
        field_check(self.mem,self.server,[item for item in FIELDS if item[1] in names])
    def probe_feature(self,key):
        if not self.mem or not self.core_verified:raise NotReady('客户端尚未通过兼容性校验')
        if key=='commands':command_entry(self);return
        if key=='chat':self.verify_command('say compatibility_probe');return
        if key=='cheats':command_entry(self);self.require_local();self.cheats_value();return
        self.require_local()
        groups={
            'roster':('m_iHealth','m_iMaxHealth','m_lifeState','m_szNetname'),
            'hp':('m_iHealth','m_iMaxHealth','m_lifeState'),
            'money':('m_iAccount','m_iMaxAccount'),
            'ammo':('m_iClip1','m_iPrimaryAmmoType','m_hMyWeapons','m_iAmmo'),
            'scale':('m_flHeadScale','m_flBodyScale'),
            'buy':('m_iUserFlag',),
        }
        if key in groups:
            self.check_fields(groups[key])
            if key!='roster':self.check_fields(groups['roster'])
            if key=='buy' and self.mem.read(self.server+0x8d990,19)!=bytes.fromhex('8b81e006000023442404f7d81bc0f7d8c20400'):
                raise NotReady('购买区标志读取路径未验证')
            return
        if key=='local_commands':command_entry(self);return
        if key in ('mutation','mutation_read'):
            self.require_zeta();self.mutation_state();command_entry(self)
            if key=='mutation' and not self.cheats_value():raise NotReady('需要先开启 sv_cheats')
            return
        if key=='machine':self.require_zeta();self.verify_machine_paths();return
        raise NotReady('未登记的功能：'+key)
    def refresh_capabilities(self):
        self.capabilities={key:probe_result(lambda k=key:self.probe_feature(k)) for key in
            ('commands','chat','local_commands','roster','hp','money','ammo','scale','buy','cheats','mutation','mutation_read','machine')}
        return self.capabilities
    def require(self,key):
        status=probe_result(lambda:self.probe_feature(key));self.capabilities[key]=status
        if not status['available']:raise NotReady(status['reason'])
    def command_status(self,text):return probe_result(lambda:self.verify_command(text))
    def verify_command(self,text):
        self.require('commands');command_bytes(text)
        for args in console_segments(text):
            name=args[0].casefold();entry=self.catalog.get(name)
            if name in ('alias','bind','bindtoggle','exec','execifexists'):
                raise ValueError('无法逐项验证延迟或间接指令，请直接填写原生命令')
            if name=='give_mutation' and (len(console_segments(text))!=1 or len(args)!=2):raise ValueError('请单独发送 give_mutation 次数')
            if name=='sv_cheats':self.require('cheats')
            if name in ('toggle','incrementvar','multvar'):
                if len(args)<2:raise ValueError('缺少变量名')
                self.verify_command(args[1])
            if name=='jointeam':self.require('local_commands');continue
            if not entry:raise NotReady('命令尚未适配或未注册：'+name)
            valid=False
            for src in entry['sources']:
                module=src['module']
                if module not in self.mods or (module=='server.dll' and not self.server):continue
                if module=='server.dll' and not self.local_connection():continue
                base,size,_=self.mods[module];obj=base+src['rva']
                try:
                    if self.mem.u32(obj+8)!=1 or self.mem.string(self.mem.u32(obj+12),128).casefold()!=name:continue
                    if entry['kind']=='command' and not base<=self.mem.u32(obj+24)<base+size:continue
                    if self.mem.u32(obj+20)&0x4000 and not self.cheats_value():continue
                except Exception:continue
                valid=True;break
            if not valid:raise NotReady('当前环境中此命令不可用：'+name)
    def current_context(self):
        m=self.mem
        if not m or not m.alive():raise NotReady('游戏进程已退出')
        if not self.core_verified:raise NotReady('客户端尚未通过兼容性校验')
        if m.i32(self.engine+9249476)!=6:raise NotReady('已连接游戏，等待进入对局')
        index=m.i32(self.engine+9249584)+1
        if not 1<=index<=64:raise NotReady('本地玩家编号尚未就绪')
        cp,cs=struct.unpack('<II',m.read(self.client+15615276+index*16,8))
        if not cp or cp!=m.u32(self.client+30259272):raise NotReady('本地角色尚未同步')
        sp=ss=0
        try:local=self.local_connection()
        except NotReady:local=False
        if self.server and local:
            sp,ss=struct.unpack('<II',m.read(self.server+0xa5fa44+index*16,8))
            if not sp or (cs&0x3ff)!=(ss&0x3ff):raise NotReady('服务器与本地角色尚未同步')
            if m.string(m.u32(sp+0x70),32)!='player':raise NotReady('服务器本地玩家未确认')
        level=m.string(self.engine+9249588,128)
        if not level:raise NotReady('地图名称尚未就绪')
        return (level,index,sp,ss,cp,cs,m.u32(self.engine+0x8d21a0))
    def snapshot(self):
        self.refresh_server()
        context=self.current_context()
        if context!=self.context:
            self.epoch+=1;self.context=context
        self.map_name,self.local_index=context[:2]
        self.refresh_capabilities();players=[]
        if not self.capabilities['roster']['available']:return players
        for index in range(1,65):
            player=self.read_player(index)
            if player:players.append(player)
        if self.current_context()!=context:raise NotReady('对局数据正在切换')
        return players
    def invalidate(self):
        if self.context is not None:self.epoch+=1;self.context=None
    def read_player(self,index):
        if not 1<=index<=64:return None
        m=self.mem;entry=self.server+0xa5fa44+index*16
        p,serial=struct.unpack('<II',m.read(entry,8))
        if not p:return None
        if m.string(m.u32(p+0x70),32)!='player':return None
        maximum,hp=struct.unpack('<ii',m.read(p+0xf0,8));life=m.read(p+0xf8,1)[0];team=m.read(p+0x201,1)[0]
        money=m.i32(p+0x1c3c) if probe_result(lambda:self.check_fields(('m_iAccount','m_iMaxAccount')))['available'] else -1;name=m.string(p+0xed0,48)
        if not -1000000<=hp<=100000000 or not 0<=maximum<=100000000 or team>16:raise NotReady('玩家字段异常，已停止读取')
        if struct.unpack('<II',m.read(entry,8))!=(p,serial):return None
        key=PlayerKey(self.epoch,self.map_name,index,p,serial)
        return Player(key,name or f'玩家 {index}',hp,maximum,money,team,life==0 and hp>0,index==self.local_index)
    def validate(self,key,alive=True):
        if key.epoch!=self.epoch or key.map_name!=self.map_name or self.current_context()!=self.context:raise NotReady('对局已变化，请刷新玩家列表')
        actual=self.read_player(key.index)
        if not actual or actual.key!=key:raise NotReady('玩家已离开或编号被复用，请重新勾选')
        if alive and not actual.alive:raise NotReady('该玩家已死亡，等待存活后操作')
        return actual
    def network_target(self,p,index):
        m=self.mem
        if m.read(p+0x68,1)!=b'\0':raise NotReady('实体正在集中更新，稍后重试')
        edict=m.u32(p+0x20)
        flags,serial,slot=struct.unpack('<Ihh',m.read(edict,8))
        if slot!=index or flags&~0xffff:raise NotReady('实体网络编号不匹配')
        return edict
    def dirty(self,p,index):
        edict=self.network_target(p,index)
        # FL_EDICT_CHANGED | FL_EDICT_FULL: regenerate the entity baseline.
        flags=self.mem.u32(edict)
        self.mem.write(edict,struct.pack('<I',flags|0x101))
    def set_player_field(self,key,offset,data,alive=True,scale=False):
        feature={0xf0:'hp',0xf4:'hp',0x1c3c:'money',0x1c40:'money',0x6f0:'scale',0x6e0:'buy'}.get(offset)
        if feature is None and 0x75c<=offset<0x7ac and offset%2==0:feature='ammo'
        if feature is None:raise NotReady('字段未登记，拒绝写入')
        self.require(feature)
        self.validate(key,alive);p=key.address
        self.network_target(p,key.index)
        if self.mem.read(p+offset,len(data))==data:return False
        if struct.unpack('<II',self.mem.read(self.server+0xa5fa44+key.index*16,8))!=(p,key.serial):raise NotReady('玩家已改变')
        self.mem.write(p+offset,data)
        if scale:self.mem.write(p+0x6fc,b'\x01')
        self.dirty(p,key.index)
        if self.mem.read(p+offset,len(data))!=data:raise NotReady('游戏已覆盖该数值，稍后重试')
        return True
    def set_health(self,key,value):
        self.require('hp')
        value=bounded_int(value,1,999999,'血量')
        self.set_player_field(key,0xf0,struct.pack('<ii',value,value))
    def set_money(self,key,value):
        self.require('money')
        value=bounded_int(value,0,999999,'金钱');self.validate(key)
        maximum=self.mem.i32(key.address+0x1c40)
        if not 0<=maximum<=100000000:raise NotReady('金钱上限字段异常')
        self.set_player_field(key,0x1c3c,struct.pack('<ii',value,max(value,maximum)))
    def set_scale(self,key,head,body):
        self.require('scale')
        head=bounded_float(head,.25,3,'头部比例');body=bounded_float(body,.25,3,'身体比例')
        self.set_player_field(key,0x6f0,struct.pack('<ff',head,body),scale=True)
    def set_buy_flag(self,key,enabled):
        self.require('buy')
        self.validate(key,alive=enabled)
        # CCSPlayer's AddUserFlag callback is a no-op in this exact build.
        # A different subclass must be reviewed before bypassing that callback.
        callback=self.mem.u32(self.mem.u32(key.address)+0x3fc)
        if callback!=self.server+0x8bb00 or self.mem.read(callback,1)!=b'\xc3':raise RuntimeError('当前角色的购买标志回调尚未验证')
        flags=self.mem.u32(key.address+0x6e0)
        self.set_player_field(key,0x6e0,struct.pack('<I',(flags|1) if enabled else (flags&~1)),alive=enabled)
    def cheats_value(self):
        m=self.mem;obj=self.engine+8565136
        if m.string(m.u32(obj+12),64)!='sv_cheats':raise NotReady('sv_cheats 原生变量未验证')
        parent=m.u32(obj+28)
        if m.string(m.u32(parent+12),64)!='sv_cheats':raise NotReady('sv_cheats 根变量未验证')
        f,value=struct.unpack('<fi',m.read(parent+48,8))
        if value not in (0,1) or f!=float(value):raise NotReady('sv_cheats 当前数值异常')
        return bool(value)
    def optional_cheats_value(self):
        if not self.capabilities.get('cheats',{}).get('available',False):return False
        try:return self.cheats_value()
        except Exception as ex:
            self.capabilities['cheats']={'available':False,'reason':str(ex)};return False
    def set_cheats(self,enabled):
        self.require('cheats')
        if type(enabled) is not bool:raise ValueError('作弊开关必须是布尔值')
        self.cheats_value();self.send('sv_cheats '+('1' if enabled else '0'))
    def mode_id(self):
        m=self.mem;s=self.server;e=self.engine
        expected=b'\x8b\x0d'+struct.pack('<I',s+0xc58fd0)+bytes.fromhex('8b01ffa0cc010000')
        if m.read(s+0x8ee40,len(expected))!=expected:raise NotReady('游戏模式读取入口未验证')
        manager=m.u32(s+0xc58fd0)
        if m.u32(m.u32(manager)+0x1cc)!=e+0x2c5850:raise NotReady('游戏模式管理器未验证')
        wanted=m.i32(manager+0x2e8);head=m.u32(manager+0x2ec);node=m.u32(head+4)
        for _ in range(64):
            if not node or node==head:break
            left,parent,right,color,index,obj,owner=struct.unpack('<7I',m.read(node,28))
            if index==wanted:
                fn=m.u32(m.u32(obj)+0x20)
                if not e<=fn<e+self.mods['engine.dll'][1] or m.read(fn,5)!=bytes.fromhex('0fb64114c3'):raise NotReady('游戏模式对象未验证')
                return m.read(obj+0x14,1)[0]
            node=left if wanted<index else right
        raise NotReady('游戏模式尚未就绪')
    def require_zeta(self):
        self.require_local()
        if self.current_context()!=self.context:raise NotReady('对局已变化')
        if self.mode_id()!=53:raise NotReady('此项仅适用于生化 ZETA（zombie_zeta）模式')
    def mutation_state(self):
        self.require_zeta();m=self.mem;s=self.server
        player=self.read_player(self.local_index)
        if not player or not player.alive:raise NotReady('本地角色需要处于存活状态')
        self.validate(player.key)
        obj=s+0x9fcb1c
        if m.string(m.u32(obj+12),64)!='give_mutation' or m.u32(obj+24)!=s+0xdff10:raise NotReady('原生变异命令未验证')
        if m.read(s+0xdb566,6)!=bytes.fromhex('005f20005f22'):raise NotReady('变异计数更新路径未验证')
        manager=m.u32(s+0xc555c8)
        if not manager:raise NotReady('变异系统未初始化')
        head=m.u32(manager+0x46c);node=m.u32(head+4)
        for _ in range(64):
            if not node or node==head or m.read(node+0xd,1)!=b'\0':break
            index=m.i32(node+0x10)
            if index==self.local_index:
                record=m.u32(node+0x14)
                if not record:break
                handle=m.u32(record+8)
                if handle&0xffff!=player.key.index or handle>>16!=player.key.serial:raise NotReady('变异记录与当前角色不同步')
                available,previous,total=struct.unpack('<3B',m.read(record+0x20,3))
                return dict(key=player.key,record=record,available=available,total=total)
            node=m.u32(node if self.local_index<index else node+8)
        raise NotReady('当前玩家尚未建立变异记录')
    def add_mutations(self,count):
        count=bounded_int(count,1,10,'单次增加次数');before=self.mutation_state()
        if max(before['available'],before['total'])+count>255:raise ValueError('原生变异计数是一个字节，本次增加会溢出，已拒绝')
        self.send(f'give_mutation {count}')
        return before
    def verify_machine_paths(self):
        m=self.mem;s=self.server
        if m.read(s+0x8c067,7)!=bytes.fromhex('c6808904000001') or m.read(s+0x8c6e3,7)!=bytes.fromhex('80bf8904000000'):raise NotReady('变异机器重抽路径未验证')
        prop=s+0xc5fd68+0x30
        if m.string(m.u32(prop),64)!='m_nPickedSkillID' or m.u32(prop+24)!=0x48c:raise NotReady('变异机器技能字段未验证')
    def machine(self,key):
        self.require_zeta()
        if key.epoch!=self.epoch or key.map_name!=self.map_name:raise NotReady('机器列表已过期，请刷新')
        m=self.mem;entry=self.server+0xa5fa44+key.index*16
        if struct.unpack('<II',m.read(entry,8))!=(key.address,key.serial):raise NotReady('机器实体已经改变，请刷新')
        if m.string(m.u32(key.address+0x70),40)!='entmutationmachine':raise NotReady('目标不是变异机器')
        enabled,pending=struct.unpack('<2B',m.read(key.address+0x488,2));skill=m.i32(key.address+0x48c)
        if enabled not in (0,1) or pending not in (0,1) or not -1<=skill<=100000:raise NotReady('变异机器状态异常')
        return MutationMachine(key,skill,bool(enabled),bool(pending))
    def machines(self):
        self.require_zeta();self.verify_machine_paths();m=self.mem;s=self.server;result=[]
        entries=m.read(s+0xa5fa44,65536*16)
        for index in range(1,65536):
            p,serial=struct.unpack_from('<II',entries,index*16)
            if not p:continue
            try:
                if m.string(m.u32(p+0x70),40)=='entmutationmachine':result.append(self.machine(PlayerKey(self.epoch,self.map_name,index,p,serial)))
            except NotReady:continue
        return result
    def reroll_machine(self,key):
        self.require('machine')
        self.verify_machine_paths();row=self.machine(key)
        if not row.enabled:raise NotReady('这台变异机器尚未启用，游戏启用后再重抽')
        if row.pending:raise NotReady('这台机器已有重抽请求，等待游戏处理')
        # Native ChangeMutationMachineSkillID(name) sets this request byte.
        # The entity's own Think then draws the skill, replicates +48C, and clears it.
        if struct.unpack('<II',self.mem.read(self.server+0xa5fa44+key.index*16,8))!=(key.address,key.serial):raise NotReady('机器已改变')
        self.mem.write(key.address+0x489,b'\x01')
        return row
    def send(self,text):
        self.verify_command(text)
        command_bytes(text)
        if self.current_context()!=self.context:raise NotReady('对局已变化，请重新连接')
        # A completed ClientCmd thread only copied the command. Native execution
        # may be many frames later; reserve this counter until readback confirms it.
        segments=console_segments(text);mutation_total=0;state=None
        for args in segments:
            if args[0].lower() in ('alias','bind','bindtoggle') and any(re.search(r'\bgive_mutation\b',arg,re.I) for arg in args[1:]):
                raise ValueError('变异命令不能放入别名或按键；请单独发送 give_mutation 次数')
            if args[0].lower()=='give_mutation':
                if len(segments)!=1 or len(args)!=2:raise ValueError('请单独发送：give_mutation 次数（1～10），不与延迟或其他命令组合')
                mutation_total=bounded_int(args[1],1,10,'变异次数')
        if mutation_total:
            state=self.mutation_state()
            if self.mem.u32(self.server+0x9fcb1c+20)&0x4000 and not self.cheats_value():raise NotReady('原生变异命令需要开启作弊功能（sv_cheats）；请等开关实际生效后再操作')
            pending=self.mutation_pending
            if pending and pending['key']==state['key'] and pending['record']==state['record']:
                if state['total']<pending['total']+pending['count']:raise NotReady('上一条变异命令尚未确认生效，不能重复累加；请等待读回。游戏拒绝后需重新连接工具')
            self.mutation_pending=None
            if max(state['available'],state['total'])+mutation_total>255:raise ValueError('本次变异命令会溢出原生计数，已拒绝')
        if not self.queue:self.queue=CommandQueue(self)
        self.queue.send(text)
        if state is not None:self.mutation_pending=dict(state,count=mutation_total)
    def refill(self,key,weapon_caps):
        self.require('ammo')
        self.validate(key);m=self.mem;p=key.address
        handles=struct.unpack('<48I',m.read(p+0x7ac,48*4))
        for handle in dict.fromkeys(handles):
            if handle in (0,0xffffffff):continue
            index=handle&0xffff;serial=handle>>16
            if not 1<=index<8192:continue
            entry=self.server+0xa5fa44+index*16
            wp,ws=struct.unpack('<II',m.read(entry,8))
            if not wp or ws!=serial:continue
            name=m.string(m.u32(wp+0x70),64)
            caps=weapon_caps.get(name)
            if not caps:continue
            clip,ammo=caps
            ammo_type=m.i32(wp+0x53c);current=m.i32(wp+0x54c)
            if not 0<=current<=1000 or not 0<clip<=255:continue
            self.validate(key);self.network_target(wp,index)
            if struct.unpack('<II',m.read(entry,8))!=(wp,ws) or handle not in struct.unpack('<48I',m.read(p+0x7ac,192)):continue
            if current<clip:
                m.write(wp+0x54c,struct.pack('<i',clip));self.dirty(wp,index)
            # This build uses forty uint16 reserve counters, NOT int32.
            if 0<=ammo_type<40 and 0<ammo<=65535:
                before=struct.unpack('<H',m.read(p+0x75c+ammo_type*2,2))[0]
                if before<ammo:self.set_player_field(key,0x75c+ammo_type*2,struct.pack('<H',ammo))
    def close(self):
        try:
            if self.queue:self.queue.close()
        finally:
            self.queue=None
            if self.mem:self.mem.close()
            self.mem=None;self.server=0;self.context=None;self.epoch+=1
            self.core_verified=False;self.capabilities={};self.next_modules=0.

def bounded_int(value,low,high,label):
    try:number=int(str(value).strip())
    except (ValueError,TypeError):raise ValueError(f'{label}必须是整数') from None
    if not low<=number<=high:raise ValueError(f'{label}范围 {low}～{high}')
    return number

def bounded_float(value,low,high,label):
    try:number=float(value)
    except (ValueError,TypeError):raise ValueError(f'{label}必须是数字') from None
    if not math.isfinite(number) or not low<=number<=high:raise ValueError(f'{label}范围 {low}～{high}')
    return number

def portable_save(path,settings,expected_digest=None):
    path=Path(path);source=path.read_bytes()
    if expected_digest and hashlib.sha256(source).hexdigest()!=expected_digest:raise RuntimeError('脚本运行期间被其他程序修改；请导出便携副本，避免覆盖修改')
    text=source.decode('utf-8-sig').replace('\r\n','\n')
    marker=r'^_PORTABLE_SETTINGS_B64 = "[A-Za-z0-9+/=]*"$'
    if len(re.findall(marker,text,re.M))!=1:raise RuntimeError('配置嵌入位置未找到，请使用桌面单文件版本')
    encoded=base64.b64encode(json.dumps(settings,ensure_ascii=False,separators=(',',':')).encode()).decode()
    output=re.sub(marker,'_PORTABLE_SETTINGS_B64 = "'+encoded+'"',text,flags=re.M)
    compile(output,str(path),'exec')
    temp=None
    try:
        with tempfile.NamedTemporaryFile('wb',prefix='.'+path.stem+'-',suffix='.tmp',dir=path.parent,delete=False) as f:
            temp=Path(f.name);f.write(output.encode('utf-8'));f.flush();os.fsync(f.fileno())
        os.replace(temp,path);temp=None
    finally:
        if temp:temp.unlink(missing_ok=True)
    return hashlib.sha256(path.read_bytes()).hexdigest()

class Controls:
    """Identity-bound locks. Disable restores limits/scale, never old health or cash."""
    def __init__(self,backend,caps):
        self.b=backend;self.caps=caps;self.keys=[];self.hp=None;self.money=None;self.ammo=False;self.scale=None;self.saved={};self.buy=False;self.buy_saved={}
    def disable_unavailable(self):
        for key in ('hp','money','ammo','scale','buy'):
            if not self.b.capabilities.get(key,{}).get('available',False):
                setattr(self,key,False if key in ('ammo','buy') else None)
    def remember(self,key,field,size):
        record=(key,field)
        if record not in self.saved:self.saved[record]=[self.b.mem.read(key.address+field,size),None]
        return self.saved[record]
    def step(self,players):
        valid={p.key for p in players};live={p.key:p for p in players if p.alive};self.keys=[k for k in self.keys if k in valid]
        # Drop restoration ownership only after a fresh, stable roster proves
        # the old entity is gone. Dead players still retain restoration records.
        self.saved={record:value for record,value in self.saved.items() if record[0] in valid}
        self.buy_saved={key:value for key,value in self.buy_saved.items() if key in valid}
        count=0
        for key in self.keys:
            if key not in live:continue
            if self.hp is not None:
                rec=self.remember(key,0xf0,4);rec[1]=struct.pack('<i',self.hp);self.b.set_health(key,self.hp);count+=1
            if self.money is not None:
                rec=self.remember(key,0x1c40,4);rec[1]=struct.pack('<i',max(self.money,self.b.mem.i32(key.address+0x1c40)));self.b.set_money(key,self.money);count+=1
        for key in live:
            if self.ammo:self.b.refill(key,self.caps);count+=1
            if self.scale:
                rec=self.remember(key,0x6f0,8);rec[1]=struct.pack('<ff',*self.scale);self.b.set_scale(key,*self.scale);count+=1
            if self.buy and live[key].local:
                if key not in self.buy_saved:self.buy_saved[key]=self.b.mem.u32(key.address+0x6e0)&1
                self.b.set_buy_flag(key,True);count+=1
        return count
    def step_isolated(self,players):
        features=('hp','money','ammo','scale','buy');values={key:getattr(self,key) for key in features};errors=[]
        try:
            for key in features:
                for other in features:setattr(self,other,values[other] if other==key else (False if other in ('ammo','buy') else None))
                if values[key] is None or values[key] is False:continue
                try:self.step(players)
                except Exception as ex:
                    values[key]=False if key in ('ammo','buy') else None
                    errors.append(key+' 已停止：'+str(ex))
        finally:
            for key,value in values.items():setattr(self,key,value)
        return errors
    def restore_buy(self):
        errors=[]
        for key,before in list(self.buy_saved.items()):
            try:
                if not before:self.b.set_buy_flag(key,False)
            except Exception as ex:errors.append(str(ex))
            else:self.buy_saved.pop(key,None)
        return errors
    def restore(self,fields=None):
        errors=[]
        for (key,field),(before,written) in list(self.saved.items()):
            if fields is not None and field not in fields:continue
            try:
                self.b.validate(key,False)
                if written is not None and self.b.mem.read(key.address+field,len(written))==written:
                    self.b.set_player_field(key,field,before,alive=False,scale=field==0x6f0)
            except Exception as ex:errors.append(str(ex))
            else:self.saved.pop((key,field),None)
        return errors
    def retry_restores(self):
        fields=set()
        if self.hp is None:fields.add(0xf0)
        if self.money is None:fields.add(0x1c40)
        if self.scale is None:fields.add(0x6f0)
        errors=self.restore(fields)
        if not self.buy:errors+=self.restore_buy()
        return errors
    def stop(self,restore=True):
        self.hp=self.money=self.scale=None;self.ammo=False;self.buy=False;self.keys=[]
        errors=self.restore() if restore else []
        if restore:errors+=self.restore_buy()
        if not restore:self.buy_saved.clear();self.saved.clear()
        return errors

class Worker(threading.Thread):
    def __init__(self,events,caps):
        super().__init__(name='CSO2 host worker',daemon=True)
        self.events=events;self.requests=queue.Queue(maxsize=128);self.quit=threading.Event();self.b=Backend();self.controls=Controls(self.b,caps);self.request_lock=threading.Lock();self.request_generation=0
        self.players=[];self.chat=None;self.last_context=None;self.tick_error='';self.last_ui=0;self.bio_pending=None;self.restore_error='';self.command_watch=[]
    def emit(self,kind,**data):self.events.put((kind,data))
    def emit_flags(self):self.emit('flags',hp=self.controls.hp is not None,money=self.controls.money is not None,ammo=self.controls.ammo,scale=self.controls.scale is not None,buy=self.controls.buy,chat=self.chat is not None)
    def submit(self,action,**data):
        with self.request_lock:
            if action in ('stop','disconnect','connect'):
                self.request_generation+=1
                while True:
                    try:self.requests.get_nowait()
                    except queue.Empty:break
            data['_generation']=self.request_generation
            try:self.requests.put_nowait((action,data));return True
            except queue.Full:
                self.emit('error',text='待执行操作已满，本次点击未提交；请等待或点击停止');self.emit_flags();return False
    def reset(self,restore=True):
        self.chat=None;self.bio_pending=None;errors=self.controls.stop(restore);self.emit('reset')
        if errors:self.emit('log',text='部分临时值尚未恢复，保持同一对局时将重试：'+errors[0])
    def execute(self,action,data):
        if data.get('_generation',self.request_generation)!=self.request_generation:return
        if action=='connect':
            self.reset();pid=self.b.connect(data.get('game'));self.players=[];self.last_context=None
            self.emit('log',text=f'版本校验通过，已连接 PID {pid}');return
        if action=='stop':self.reset();self.emit('log',text='已停止持续功能与定时喊话');return
        if action=='disconnect':self.reset();self.b.close();self.players=[];self.emit('state',ready=False,text='已断开',players=[]);return
        if not self.b.mem:raise NotReady('请先连接游戏')
        if data.get('epoch')!=self.b.epoch:raise NotReady('对局或连接已变化，本次操作未执行')
        if self.b.current_context()!=self.b.context:raise NotReady('对局已变化，本次操作未执行')
        feature={'cheats':'cheats','ammo':'ammo','buy':'buy','scale':'scale','mutation_add':'mutation','mutation_read':'mutation_read','machine_scan':'machine','machine_reroll':'machine','chat':'chat','chat_timer':'chat'}.get(action)
        if feature and data.get('enabled',True):self.b.require(feature)
        if action=='locks':
            for key in ('hp','money'):
                if data.get(key) is not None:self.b.require(key)
        if action=='once':self.b.require(data['field'])
        if action=='command':
            self.b.send(data['text']);self.emit('log',text='已交给游戏命令队列：'+data['text']);return
        if action=='chat':
            self.b.send(chat_command(data['text'],data['team']));self.emit('log',text='喊话已交给游戏命令队列');return
        if action=='chat_timer':
            if not data['enabled']:self.chat=None;self.emit('log',text='定时喊话已停止');return
            cmd=chat_command(data['text'],data['team']);interval=bounded_float(data['interval'],1,3600,'喊话间隔')
            self.chat=(cmd,interval,time.monotonic()+interval,self.b.epoch);self.emit('log',text=f'定时喊话已开始，每 {interval:g} 秒一次');return
        if action=='mutation_read':
            state=self.b.mutation_state();self.emit('bio_state',text=f'自身当前变异次数：{state["available"]}');return
        if action=='mutation_add':
            if self.bio_pending:raise NotReady('上一条生化请求尚未核对完成')
            count=bounded_int(data['count'],1,10,'单次增加次数');before=self.b.add_mutations(count);before['requested']=count
            self.bio_pending=('mutation',before,time.monotonic()+1.,time.monotonic()+10.)
            self.emit('log',text='增加变异次数已交给游戏；等待读取结果');return
        if action=='machine_scan':
            rows=self.b.machines();self.emit('machines',rows=rows);self.emit('log',text=f'发现 {len(rows)} 台变异机器');return
        if action=='machine_reroll':
            if self.bio_pending:raise NotReady('上一条生化请求尚未核对完成')
            before=self.b.reroll_machine(data['key']);self.bio_pending=('machine',before,time.monotonic()+1.,time.monotonic()+10.)
            self.emit('log',text=f'机器 #{before.key.index} 重抽请求已设置，等待游戏 Think 处理');return
        if action=='locks':
            keys=data['keys']
            if (data['hp'] is not None or data['money'] is not None) and not keys:raise ValueError('请先勾选玩家')
            for key in keys:self.b.validate(key,False)
            hp=bounded_int(data['hp'],1,999999,'血量') if data['hp'] is not None else None
            cash=bounded_int(data['money'],0,999999,'金钱') if data['money'] is not None else None
            self.controls.hp=self.controls.money=None
            errors=self.controls.restore({0xf0,0x1c40})
            if errors:raise RuntimeError('旧锁定已停止，但临时上限尚未恢复：'+errors[0])
            self.controls.keys=keys;self.controls.hp=hp;self.controls.money=cash
            self.emit('log',text=f'玩家锁定已更新，目标 {len(keys)} 人');return
        if action=='once':
            if not data['keys']:raise ValueError('请先勾选玩家')
            value=bounded_int(data['value'],1 if data['field']=='hp' else 0,999999,'数值')
            for key in data['keys']:self.b.validate(key)
            done=0
            try:
                for key in data['keys']:
                    if data['field']=='hp':self.b.set_health(key,value)
                    else:self.b.set_money(key,value)
                    done+=1
            except Exception as ex:raise RuntimeError(f'已应用 {done} 人；后续停止：{ex}') from ex
            self.emit('log',text=f'数值已写入 {done} 名存活玩家');return
        if action=='ammo':
            self.controls.ammo=bool(data['enabled']);self.emit('log',text='全局弹药补满：'+('开启' if data['enabled'] else '关闭'));return
        if action=='cheats':
            enabled=data['enabled']
            self.b.set_cheats(enabled)
            import cheat_settings as module
            try:module.save_enabled(enabled,expected_game=self.b.game)
            except Exception as ex:self.emit('error',text='游戏指令已入队，但本地服务器设置未同步：'+str(ex))
            else:self.emit('log',text='已同步本地服务器的作弊设置')
            self.emit('log',text='sv_cheats 设置已入队，状态以游戏实值为准');return
        if action=='buy':
            self.controls.buy=bool(data['enabled'])
            if not self.controls.buy:
                errors=self.controls.restore_buy()
                if errors:raise RuntimeError('购买锁定已停止，但临时标志尚未恢复：'+errors[0])
            self.emit('log',text='随时购买枪械：'+('开启' if data['enabled'] else '关闭'));return
        if action=='scale':
            scale=(bounded_float(data['head'],.25,3,'头部比例'),bounded_float(data['body'],.25,3,'身体比例')) if data['enabled'] else None
            self.controls.scale=None;errors=self.controls.restore({0x6f0})
            if errors:raise RuntimeError('比例锁定已停止，但部分模型尚未恢复：'+errors[0])
            self.controls.scale=scale;self.emit('log',text='全局模型比例：'+(f'头部 {scale[0]:g} / 身体 {scale[1]:g}' if scale else '已恢复'));return
        raise ValueError('未知操作：'+action)
    def run(self):
        try:
            while not self.quit.is_set():
                try:action,data=self.requests.get(timeout=.05)
                except queue.Empty:action=None
                if action:
                    try:self.execute(action,data)
                    except Exception as ex:
                        self.emit('error',text=str(ex));self.emit_flags()
                if not self.b.mem:continue
                try:
                    players=self.b.snapshot()
                    if self.last_context is not None and self.last_context!=self.b.epoch:
                        self.reset(False);self.emit('log',text='对局或本地角色已变化，持续功能已停止，请重新勾选')
                    self.last_context=self.b.epoch;self.players=players
                    self.controls.disable_unavailable()
                    for message in self.controls.step_isolated(players):self.emit('error',text=message);self.emit_flags()
                    restore_errors=self.controls.retry_restores()
                    restore_message=restore_errors[0] if restore_errors else ''
                    if restore_message and restore_message!=self.restore_error:self.emit('error',text='临时值仍待恢复，将继续重试：'+restore_message)
                    if not restore_message and self.restore_error:self.emit('log',text='待恢复的临时值已处理')
                    self.restore_error=restore_message
                    if self.b.queue:self.b.queue.poll()
                    if self.chat:
                        cmd,interval,due,epoch=self.chat
                        if epoch!=self.b.epoch:self.chat=None;self.emit('reset')
                        elif time.monotonic()>=due:
                            try:self.b.send(cmd);self.chat=(cmd,interval,time.monotonic()+interval,epoch);self.emit('log',text='定时喊话已交给游戏命令队列')
                            except Exception as ex:self.chat=None;self.emit('error',text='定时喊话已停止：'+str(ex));self.emit_flags()
                    if self.bio_pending and time.monotonic()>=self.bio_pending[2]:
                        kind,before,_,deadline=self.bio_pending;self.bio_pending=None
                        try:
                            waiting=False
                            if kind=='mutation':
                                now=self.b.mutation_state()
                                if now['key']!=before['key'] or now['record']!=before['record']:raise NotReady('变异记录已变化，请重新读取')
                                waiting=now['total']<before['total']+before['requested']
                                text=f'自身当前变异次数：{now["available"]}'
                                text+='；尚未观察到预期增加，继续等待游戏' if waiting else f'；已观察到累计次数增加 {now["total"]-before["total"]}'
                            else:
                                now=self.b.machine(before.key)
                                waiting=now.pending
                                text=f'机器 #{now.key.index}：'+('游戏尚未处理重抽请求' if waiting else f'重抽已处理，当前技能 ID {now.skill}')
                            if waiting:
                                if time.monotonic()<deadline:self.bio_pending=(kind,before,time.monotonic()+1.,deadline)
                                else:text+='；核对超时，未确认成功，请读取当前状态'
                            self.emit('bio_state',text=text);self.emit('log',text=text)
                        except Exception as ex:self.emit('error',text='生化结果核对：'+str(ex))
                    self.tick_error=''
                    if time.monotonic()-self.last_ui>.4:
                        self.emit('state',ready=True,text=f'{self.b.map_name} · {len(players)} 名玩家',players=players,epoch=self.b.epoch,pid=self.b.mem.pid,cheats=self.b.optional_cheats_value(),capabilities=self.b.capabilities,command_status={text:self.b.command_status(text) for text in self.command_watch[:128]})
                        self.emit_flags()
                        self.last_ui=time.monotonic()
                except Exception as ex:
                    # A field-write error is not a new match. Preserve identity
                    # and restoration records while the same context is valid.
                    try:stable=self.b.context is not None and self.b.current_context()==self.b.context
                    except Exception:stable=False
                    if self.chat or self.controls.hp is not None or self.controls.money is not None or self.controls.ammo or self.controls.scale or self.controls.buy:self.reset(stable)
                    if not stable:self.b.invalidate()
                    message=str(ex)
                    if message!=self.tick_error:
                        self.emit('state',ready=False,text=message,players=[],epoch=self.b.epoch,capabilities={});self.tick_error=message
                    self.quit.wait(.3)
        finally:
            self.reset();self.b.close();self.emit('closed')
'''

# --- host_specs ---
MODULE_SOURCES['host_specs'] = r'''COMPAT_SPECS = {'client.dll': {'layout_hash': '956fcf3b1bda3f6fbb8b025c3e68d12a81d2980b69c71b4f94db46f70489bca1', 'anchors': {'local_player': [{'pattern': '140000000066c7461c0000c744241001000000a148b8cd11c706fce1bf1085c0740d50c7461400000000e836c07c008b4c24088bc65e64890d0000000083c410', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffff00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}, {'pattern': '140000000066c7461c0000c744241001000000a148b8cd11c706e038c21085c0740d50c7461400000000e846607c008b4c24088bc65e64890d0000000083c410', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffff00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}], 'entity_entries': [{'pattern': '740fb7f0c1e604c1e81039863045ee10756383be2c45ee1000745a39863045ee1075088bb62c45ee10eb0233f680be1f0200000075108b068bce8b80d8010000', 'mask': 'ffffffffffffffffffffffff00000000ffffffff00000000ffffffffff00000000ffffffff00000000ffffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}, {'pattern': '6383be2c45ee1000745a39863045ee1075088bb62c45ee10eb0233f680be1f0200000075108b068bce8b80d8010000ffd084c074260fb786780200008d8e3c02', 'mask': 'ffffff00000000ffffffffff00000000ffffffff00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}], 'highest_entity': [{'pattern': 'b445061100000000c644240c04b92845ee10c7056045fe10ffffffffc7055845fe1000000000e8780000008b4c2404b82845ee1064890d0000000083c410c3cc', 'mask': '00000000ffffffffffffffffffff00000000ffff00000000ffffffffffff00000000ffffffffffffffffffffffffffff00000000ffffffffffffffffffffffff', 'operand': 20}], 'attack': [{'pattern': '442404bae670be108338017e068b900c040000b9bc510b11e8b20a0000c705ecc0cd1100000000c3cccccccccccccc8b442404bae670be108338017e068b900c', 'mask': 'ffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffff00000000ffffffffffffffffffffffffffffffffff00000000ffffffffffffffff', 'operand': 20}, {'pattern': '442404bae670be108338017e068b900c040000b9bc510b11e9120a0000cccc8b442404bae670be108338017e068b900c040000b958520b11e9620a0000cccc8b', 'mask': 'ffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffff', 'operand': 20}], 'attack2': [{'pattern': '442404bae670be108338017e068b900c040000b9c8510b11e992070000cccc8b442404bae670be108338017e068b900c040000b9c8510b11e902070000cccc8b', 'mask': 'ffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffff', 'operand': 20}, {'pattern': '442404bae670be108338017e068b900c040000b9c8510b11e902070000cccc8b442404bae670be108338017e068b900c040000b980d3ec10e952070000cccc8b', 'mask': 'ffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffff', 'operand': 20}], 'netprop:m_iHealth': [{'pattern': '0000e87d8d060085dbc70500c0ce110081c410b93cc0ce11c7052cc0ce111c1200000f44f7c70504c0ce1100000000c70508c0ce1100000000893520c0ce11e8', 'mask': 'ffffffffffffffffffffff0000000000000000ff00000000ffff00000000ffffffffffffffffff00000000ffffffffffff00000000ffffffffffff00000000ff', 'operand': 20}, {'pattern': '0000893520c0ce11e8408d0600b978c0ce11c7053cc0ce110059c210c70568c0ce1198000000c70540c0ce1100000000c70544c0ce1100000000c7055cc0ce11', 'mask': 'ffffffff00000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}], 'netprop:m_iTeamNum': [{'pattern': '00c7050ca7ce1100000000c60500a7ce1100c705f0a6ce11845cc410c7051ca7ce11a0000000c705f4a6ce1100000000c705f8a6ce1100000000c70540a7ce11', 'mask': 'ffffff00000000ffffffffffff00000000ffffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}, {'pattern': '00000000c70598a6ce1150848a10e85d590700b9f0a6ce11c705b4a6ce116c5cc410c705e0a6ce11ec020000be602d8310c705b8a6ce1101000000c705bca6ce', 'mask': 'ffffffffffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffff00000000ffff00000000ffffffffffff000000', 'operand': 20}], 'netprop:m_hActiveWeapon': [{'pattern': '90858a10c705eca0ce114c0b0711e8fcaa0700b93ca1ce11c70500a1ce11ac50c410c7052ca1ce1100000000bed0819110c70504a1ce1106000000c70508a1ce', 'mask': '00000000ffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffff00000000ffff00000000ffffffffffff000000', 'operand': 20}, {'pattern': '28a1ce11981aee10e8b1aa0700bbd0819110c7053ca1ce11bc50c41085dbc70568a1ce110c0f0000bf70818a10c70540a1ce11000000000f44f7c70544a1ce11', 'mask': '0000000000000000ffffffffffff00000000ffff0000000000000000ffffffff00000000ffffffffff00000000ffff00000000ffffffffffffffffff00000000', 'operand': 20}], 'netprop:m_Local': [{'pattern': '11b988b7ce11c744245000000000e8ae870600b9c4b7ce11c70588b7ce114071be10c705b4b7ce1100000000c7058cb7ce1100000000c70590b7ce1100000000', 'mask': '00ff00000000ffffffffffffffffffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffff', 'operand': 20}, {'pattern': 'a8b7ce1170818a10e872870600b900b8ce11c705c4b7ce11a07ec410c705f0b7ce116c0f0000c705c8b7ce1106000000c705ccb7ce1100000000c705e8b7ce11', 'mask': '0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}], 'netprop:m_vecPunchAngle': [{'pattern': '00000000c70520b0ce1150848a10e87c7d0600b978b0ce11c7053cb0ce11287cc410c70568b0ce1158000000c70540b0ce1101000000c70544b0ce1100000000', 'mask': 'ffffffffffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffff', 'operand': 20}, {'pattern': '5cb0ce1150848a10e8407d0600b9b4b0ce11c70578b0ce113c7cc410c705a4b0ce116c000000c7057cb0ce1102000000c70580b0ce1100000000c70598b0ce11', 'mask': '0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}], 'netprop:m_vecOrigin': [{'pattern': '000000b95ca4ce11893540a4ce11e8d05b0700b998a4ce11c7055ca4ce11b45cc410c70588a4ce1178000000c70560a4ce1100000000c70564a4ce1100000000', 'mask': 'ffffffff00000000ffff00000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffff', 'operand': 20}, {'pattern': '7ca4ce1190808a10e8945b0700b9d4a4ce11c70598a4ce111050c210c705c4a4ce11d0030000c7059ca4ce1102000000c705a0a4ce1100000000c705b8a4ce11', 'mask': '0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}], 'netprop:m_iClip1': [{'pattern': '00c705b450ce1100000000c605a850ce1100c7059850ce11d02bc210c705c450ce11300a0000c7059c50ce1100000000c705a050ce1100000000c705e850ce11', 'mask': 'ffffff00000000ffffffffffff00000000ffffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}, {'pattern': '90858a10c7054850ce116004ee10e8861e1500b99850ce11c7055c50ce11602dc210c7058850ce1100000000be40819110c7056050ce1106000000c7056450ce', 'mask': '00000000ffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffff00000000ffff00000000ffffffffffff000000', 'operand': 20}], 'netprop:m_hMyWeapons': [{'pattern': '4120f30f7e842488000000660fd64130894138b978a1ce11e85bab070083c44c8b4c2448b8010000005f5ec705ac1aee10c4a0ce11c705b01aee1004000000c7', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffffffffffffffffffffffffffffffffffffffffff0000000000000000ffff00000000ffffffffff', 'operand': 20}], 'netprop:m_iAmmo': [{'pattern': '4120f30f7e842488000000660fd64130894138b92cb9ce11e8f786060083c44cb968b9ce11e87a850600b9a4b9ce11c70568b9ce11707ec410c70594b9ce1170', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffffffffffffffffff00000000ffffffffffff00000000ffff0000000000000000ffff00000000ff', 'operand': 20}], 'netprop:m_iPrimaryAmmoType': [{'pattern': '00c705904ece1100000000c605844ece1100c705744ece11b02bc210c705a04ece11200a0000c705784ece1100000000c7057c4ece1100000000c705944ece11', 'mask': 'ffffff00000000ffffffffffff00000000ffffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}, {'pattern': '50000000c705844fce11f0818a10c7056004ee10744ece11c7056404ee1005000000c7056804ee1000000000c7056c04ee10dc2cc21066c7057004ee100000c3', 'mask': 'ffffffffffff0000000000000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff0000000000000000ffffff00000000ffffff', 'operand': 20}], 'netprop:m_hRagdoll': [{'pattern': '05040dd01100b9102e9b10a3140dd01185c9c705f40cd0115cfbc910b8102e9b10c705200dd011881600000f44c6c705f80cd01100000000c705fc0cd0110000', 'mask': 'ff00000000ffff00000000ff00000000ffffffff0000000000000000ff00000000ffff00000000ffffffffffffffffff00000000ffffffffffff00000000ffff', 'operand': 20}, {'pattern': '00000000c7059c0cd01170818a10e86967efffb9f40cd011c705b80cd01140fbc910c705e40cd0112c160000bed0819110c705bc0cd01101000000c705c00cd0', 'mask': 'ffffffffffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffff00000000ffff00000000ffffffffffff000000', 'operand': 20}], 'netprop:m_bRedraw': [{'pattern': '00000000c705c83dd01170818a10e88591ebffb9203ed011c705e43dd0115871be10c705103ed01100000000c705e83dd01106000000c705ec3dd01100000000', 'mask': 'ffffffffffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffff', 'operand': 20}, {'pattern': '0c3ed01178fd0611e83f91ebffb95c3ed011c705203ed011f004cb10c7054c3ed011a80b0000c705243ed01100000000c705283ed01100000000c705403ed011', 'mask': '0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}], 'netprop:m_fThrowTime': [{'pattern': '00000000c705403ed01190808a10e80391ebffb9983ed011c7055c3ed011fc04cb10c705883ed011a90b0000c705603ed01100000000c705643ed01100000000', 'mask': 'ffffffffffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffff', 'operand': 20}, {'pattern': '000000c7057c3ed01190808a10e8c790ebffc705983ed011c804cb10c705c43ed011ac0b0000c7059c3ed01101000000c705a03ed01100000000c705b83ed011', 'mask': 'ffffffffff0000000000000000ffffffffffffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}]}}, 'engine.dll': {'layout_hash': '7f933de0f77709684092df7ceb7eb5813a621e09ac9b4b9f26cbf21ae610cdc0', 'anchors': {'local_index': [{'pattern': '10ff502884db7413a1c0b98210b9c0b98210ff3530238d10ff50288b068bce68004000008b4008ffd084c07475e8db39050084c0756c833db46e70100074128b', 'mask': '00ffffffffffffffff00000000ff00000000ffff00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000ffffffff', 'operand': 20}, {'pattern': '0f114610e8995725008b0dc002901185c97428a130238d108b114050ff520c85c074188b108bc8ff52248b08894e088b4804894e0c8b4008894610f30f104610', 'mask': 'ffffffffffffffffffffff00000000ffffffffff00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}], 'signon': [{'pattern': 'c3ccccccccccccccb804000000e8961c4a00833dc4228d10068b411c7c12f30f2c4830e890a90e00890424db042459c3d9403059c3cccccc64a1000000006aff', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}, {'pattern': '442404f30f110424837834000f84a9000000833dc4228d10060f8c9c000000a130497510b9304975108b4044ffd0d82c24a1ccb58210f30f104830d91c24f30f', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffffffffffffffff00000000ff00000000ffffffffffffffffff00000000ffffffffffffffffffff', 'operand': 20}], 'view_angles': [{'pattern': '0f28ca8b0dd0029011f30f114c240cf30f5cca68642c9110f30f580d682c9110f30f110d682c91108b01ff5034f30f1044240cf30f1105882c9110f30f104424', 'mask': 'ffffffffff00000000ffffffffffffffffffffff00000000ffffffff00000000ffffffff00000000ffffffffffffffffffffffffffffff00000000ffffffffff', 'operand': 20}, {'pattern': 'c20400cccccccccccccccccc8b442404f30f1005642c9110f30f1100f30f1005682c9110f30f114004f30f10056c2c9110f30f114008c20400cccccc568b7424', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffffffffffffffff00000000ffffffffffffffffff00000000ffffffffffffffffffffffffffffff', 'operand': 20}], 'render': [{'pattern': 'ccccccb820747010c3ccccccccccccccccccccb9c0eba310a1c0eba310ff6034ccccccb9c0eba310a1c0eba310ff6030cccccca140f2a310485678218b3534f2', 'mask': 'ffffffff00000000ffffffffffffffffffffffff00000000ff00000000ffffffffffffff00000000ff00000000ffffffffffffff00000000ffffffffffff0000', 'operand': 20}, {'pattern': '747010c3ccccccccccccccccccccb9c0eba310a1c0eba310ff6034ccccccb9c0eba310a1c0eba310ff6030cccccca140f2a310485678218b3534f2a3108bc88b', 'mask': '000000ffffffffffffffffffffffff00000000ff00000000ffffffffffffff00000000ff00000000ffffffffffffff00000000ffffffffffff00000000ffffff', 'operand': 20}], 'level_name': [{'pattern': 'cccccccccccccccccc803dec0f801000750d803d34238d10000f849f000000833d006f701001751e8b0de09b6e108b018b4018ffd084c00f85810000008b4c24', 'mask': 'ffffffffffffffffffffff00000000ffffffffff00000000ffffffffffffffffff00000000ffffffffff00000000ffffffffffffffffffffffffffffffffffff', 'operand': 20}, {'pattern': '69f9ff83c4105ec3cccccccccccccccccccc803d34238d1000742f833d006f701001751a8b0de09b6e108b018b4018ffd084c075158b4c2404e93452faff6a01', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffffffffff00000000ffffffffff00000000ffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}]}}}
'''

# --- launcher ---
MODULE_SOURCES['launcher'] = r'''"""CSO2 local launcher and background supervisor (Python standard library only)."""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import winreg

BASE = Path(__file__).resolve().parent
CONFIG_PATH = BASE / 'local_config.json'
LOGS = BASE / 'logs'
NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def config():
    from game_paths import load_local_config
    return load_local_config(CONFIG_PATH)


def atomic_json(path, value):
    if Path(path).resolve() == CONFIG_PATH.resolve():
        from game_paths import portable_local_config
        value = portable_local_config(value, CONFIG_PATH)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    os.replace(tmp, path)


def rpc(route, payload=None, timeout=3):
    cfg = config()
    req = urllib.request.Request(
        f'http://127.0.0.1:{cfg["control_port"]}{route}',
        data=None if payload is None else json.dumps(payload).encode(),
        headers={'Content-Type': 'application/json', 'X-Local-Token': cfg['control_token']},
    )
    try:
        with OPENER.open(req, timeout=timeout) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        try:
            reason = json.loads(error.read()).get('error', str(error))
        except Exception:
            reason = str(error)
        raise RuntimeError(reason) from error
    if result.get('instance') != cfg['instance']:
        raise RuntimeError('本地控制端口被其他程序占用。')
    return result


def server_banner(timeout=1):
    with socket.create_connection(('127.0.0.1', 30001), timeout) as sock:
        sock.settimeout(timeout)
        return sock.recv(64).startswith(b'~SERVERCONNECTED\n')


def migrate_saved_account(cfg):
    """Refresh a migrated account only after the old service has stopped."""
    import shutil
    old = cfg.get('migration_source')
    if not old:
        return
    source = Path(old) / 'server/CSO2-Server/database/json'
    destination = BASE / 'server/CSO2-Server/database/json'
    destination.mkdir(parents=True, exist_ok=True)
    for item in source.glob('*'):
        if item.is_file():
            target = destination / item.name
            if not target.exists() or item.stat().st_mtime_ns > target.stat().st_mtime_ns:
                if target.exists():
                    backup = BASE / 'backups' / time.strftime('%Y%m%d_%H%M%S') / 'database'
                    backup.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(target, backup / item.name)
                shutil.copy2(item, target)
    cfg.pop('migration_source', None)
    atomic_json(CONFIG_PATH, cfg)


def start_server():
    try:
        status = rpc('/health')
        if status['ready']:
            cfg = config()
            active_root = status.get('game_root')
            if active_root is None and cfg.get('migration_source'):
                old_config = Path(cfg['migration_source']) / 'local_config.json'
                if old_config.exists():
                    active_root = json.loads(old_config.read_text(encoding='utf-8')).get('game_root')
            if active_root and Path(active_root).resolve() != Path(cfg['game_root']).resolve():
                raise RuntimeError('已保存新路径；当前服务仍使用原客户端。请在退出对局后停止服务，再从此入口启动。')
            return status
        raise RuntimeError('后台已启动，但游戏服务尚未就绪，请查看日志。')
    except (urllib.error.URLError, ConnectionError, TimeoutError):
        pass
    from game_paths import validate_game
    cfg = config()
    if not validate_game(cfg.get('game_root', '')):
        raise RuntimeError('请先选择文件夹并扫描有效的 CSO2 客户端。')
    LOGS.mkdir(exist_ok=True)
    with (LOGS / 'supervisor.log').open('ab') as output:
        proc = subprocess.Popen(
            [sys.executable, str(BUNDLE_ENTRY), '--serve'],
            cwd=BASE, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
            creationflags=NO_WINDOW,
        )
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError('本地后台启动失败，请查看 logs/supervisor.log。')
        try:
            status = rpc('/health', timeout=0.6)
            if status['ready']:
                return status
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(0.15)
    raise RuntimeError('等待本地后台启动超时，请查看日志。')


def game_arguments(cfg):
    from display_settings import arguments
    account = cfg['account']
    return [
        str(Path(cfg['game_root']) / 'Bin/CounterStrikeOnline2.exe'),
        '-masterip', '127.0.0.1', '-lang', 'schinese',
        '-username', account['username'], '-password', account['password'],
        '-enablecustom', '-enableconsole',
    ] + arguments(cfg)


def enforce_windowed_settings(cfg=None):
    from display_settings import registry_values
    key = r'Software\Nexon\cso2\Settings'
    values = registry_values(cfg or config())
    snapshot = BASE / 'video_settings_backup.json'
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_READ | winreg.KEY_WRITE) as registry:
        if not snapshot.exists():
            original = {}
            for name in values:
                try:
                    value, kind = winreg.QueryValueEx(registry, name)
                    original[name] = {'exists': True, 'value': value, 'type': kind}
                except FileNotFoundError:
                    original[name] = {'exists': False}
            atomic_json(snapshot, {'key': key, 'values': original})
        for name, value in values.items():
            winreg.SetValueEx(registry, name, 0, winreg.REG_DWORD, value)
        for name, value in values.items():
            if winreg.QueryValueEx(registry, name) != (value, winreg.REG_DWORD):
                raise RuntimeError('窗口配置写入校验失败：' + name)


def owned_windows(pid):
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    windows = []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    @callback_type
    def collect(hwnd, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid:
            windows.append(hwnd)
        return True

    user32.EnumWindows(collect, 0)
    return windows


def minimize_test_game(proc):
    """Keep only the explicitly launched verification process out of the foreground."""
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    for _ in range(120):
        if proc.poll() is not None:
            return
        for hwnd in owned_windows(proc.pid):
            if user32.IsWindowVisible(hwnd) and not user32.IsIconic(hwnd):
                user32.ShowWindowAsync(hwnd, 7)  # SW_SHOWMINNOACTIVE
        time.sleep(0.5)


class Supervisor:
    def __init__(self):
        self.cfg = config()
        self.server = None
        self.game = None
        self.game_is_test = False
        self.ready = False
        self.lock = threading.RLock()
        self.files = []
        self.logs = LOGS
        self.http = None

    def status(self):
        return {
            'instance': self.cfg['instance'],
            'ready': self.ready and self.server is not None and self.server.poll() is None,
            'server_pid': None if self.server is None else self.server.pid,
            'game_pid': self.game.pid if self.game is not None and self.game.poll() is None else None,
            'supervisor_pid': os.getpid(),
            'window': f"{self.cfg.get('width',1280)}x{self.cfg.get('height',720)}",
            'windowed': self.cfg.get('windowed',True),
            'settings_api': 1,
            'memory_settings_api': 1,
            'client_cache_patch_api': 1,
            'base': str(BASE),
            'game_root': self.cfg['game_root'],
            'username': self.cfg['account']['username'],
        }

    def start_native(self):
        for port in (30001, 30002):
            kind = socket.SOCK_STREAM if port == 30001 else socket.SOCK_DGRAM
            with socket.socket(socket.AF_INET, kind) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                try:
                    probe.bind(('127.0.0.1', port))
                except OSError as error:
                    raise RuntimeError(f'端口 {port} 已被占用，未停止或修改其他程序。') from error
        from game_paths import validate_game
        from server_updates import install_pending
        install_pending(BASE)
        if not validate_game(self.cfg.get('game_root', '')):
            raise RuntimeError('客户端路径无效，请先选择文件夹并扫描。')
        migrate_saved_account(self.cfg)
        env = os.environ.copy()
        env['CSO2_LOCAL_USERNAME'] = self.cfg['account']['username']
        env['CSO2_LOCAL_PASSWORD'] = self.cfg['account']['password']
        env['CSO2_CLIENT_ROOT'] = self.cfg['game_root']
        env['CSO2_LOCAL_SOLO'] = '1'
        env['CSO2_LOCAL_SETTINGS'] = str(CONFIG_PATH)
        native = BASE / 'server/CSO2-LocalServer.exe'
        # A clean release has no account database; native mkdir is not recursive.
        for folder in ('json', 'report'):
            (native.parent / 'CSO2-Server/database' / folder).mkdir(parents=True, exist_ok=True)
        output = (LOGS / 'server.log').open('ab', buffering=0)
        self.files.append(output)
        self.server = subprocess.Popen(
            [str(native)], cwd=native.parent, env=env, stdin=subprocess.PIPE,
            stdout=output, stderr=output, creationflags=NO_WINDOW,
        )
        for _ in range(80):
            if self.server.poll() is not None:
                raise RuntimeError('服务端已退出，请查看 logs/server.log。')
            try:
                if server_banner(0.2):
                    # Account initialization follows binding the game port.
                    account_file = native.parent / 'CSO2-Server/database/json' / self.cfg['account']['username']
                    if account_file.is_file():
                        self.ready = True
                        from cheat_settings import start_monitor
                        try:
                            start_monitor(os.getpid())
                        except OSError as exc:
                            print('SV_CHEATS_MONITOR_START_FAILED', str(exc), flush=True)
                        atomic_json(BASE / 'runtime_state.json', self.status())
                        return
            except (OSError, TimeoutError):
                pass
            time.sleep(0.15)
        raise RuntimeError('服务端未能在规定时间内完成初始化。')

    def launch(self, silent=False):
        with self.lock:
            if silent:
                raise RuntimeError('静默验证请使用 --test-login；该模式在独立不可见桌面运行。')
            if not self.status()['ready']:
                raise RuntimeError('本地服务端未就绪。')
            if self.game is not None and self.game.poll() is None:
                raise RuntimeError('本地游戏已经运行，请先退出当前游戏。')
            fresh = config()
            if Path(fresh['game_root']).resolve() != Path(self.cfg['game_root']).resolve():
                raise RuntimeError('客户端目录已经更改，请先停止服务再重新启动。')
            from server_rules import apply_rule
            apply_rule(self.cfg['game_root'], fresh.get('rules', {}).get('protect_human_selection', False))
            executable = Path(self.cfg['game_root']) / 'Bin/CounterStrikeOnline2.exe'
            if not executable.is_file():
                raise RuntimeError('找不到游戏客户端。')
            self.cfg.update({key:fresh[key] for key in ('width','height','windowed','borderless','low_memory') if key in fresh})
            from client_cache_patch import before_launch as apply_client_cache_patch
            apply_client_cache_patch(self.cfg['game_root'])
            from memory_settings import apply as apply_memory_settings
            apply_memory_settings(bool(self.cfg.get('low_memory',False)),BASE)
            enforce_windowed_settings(self.cfg)
            output = (LOGS / ('game_test.log' if silent else 'game.log')).open('ab', buffering=0)
            self.files.append(output)
            startup = subprocess.STARTUPINFO()
            if silent:
                startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startup.wShowWindow = 7
            self.game = subprocess.Popen(
                game_arguments(self.cfg), cwd=executable.parent,
                stdout=output, stderr=output, stdin=subprocess.DEVNULL,
                startupinfo=startup, creationflags=NO_WINDOW,
            )
            self.game_is_test = silent
            from client_diagnostics import start as start_diagnostics
            start_diagnostics(self.game.pid,self.cfg['game_root'])
            if silent:
                threading.Thread(target=minimize_test_game, args=(self.game,), daemon=True).start()
            atomic_json(BASE / 'runtime_state.json', self.status())
            return self.status()

    def close_test_game(self):
        with self.lock:
            if self.game is not None and self.game.poll() is None:
                if not self.game_is_test:
                    raise RuntimeError('当前游戏由用户启动，后台测试入口不会关闭它。')
                user32 = ctypes.WinDLL('user32', use_last_error=True)
                for hwnd in owned_windows(self.game.pid):
                    user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
                try:
                    self.game.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    # This process was created and retained by this supervisor only.
                    self.game.terminate()
                    self.game.wait(timeout=5)
            return self.status()

    def save(self):
        with self.lock:
            if self.server is not None and self.server.poll() is None:
                self.server.stdin.write(b'save\n')
                self.server.stdin.flush()
            return self.status()

    def shutdown(self):
        with self.lock:
            if self.game is not None and self.game.poll() is None:
                raise RuntimeError('请先退出游戏，再停止本地服务端。')
            if self.server is not None and self.server.poll() is None:
                self.server.stdin.write(b'shutdown\n')
                self.server.stdin.flush()
                self.server.wait(timeout=15)
            self.ready = False
            return self.status()

    def run(self):
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def send_json(self, code, value):
                value['instance'] = owner.cfg['instance']
                data = json.dumps(value).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except (ConnectionError, OSError):
                    pass  # A short health check may already have disconnected.

            def do_GET(self):
                if self.path == '/health':
                    self.send_json(200, owner.status())
                else:
                    self.send_json(404, {'error': 'Not found'})

            def do_POST(self):
                if self.headers.get('X-Local-Token') != owner.cfg['control_token']:
                    return self.send_json(403, {'error': 'Forbidden'})
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 <= length <= 4096:
                        raise ValueError('Invalid request size')
                    data = json.loads(self.rfile.read(length) or b'{}')
                    if self.path == '/launch':
                        result = owner.launch(bool(data.get('silent')))
                    elif self.path == '/solo-room':
                        from local_modes import request_solo_room
                        result = request_solo_room(owner, data.get('mode_id'), data.get('map_id'))
                    elif self.path == '/close-test-game':
                        result = owner.close_test_game()
                    elif self.path == '/save':
                        result = owner.save()
                    elif self.path == '/shutdown':
                        result = owner.shutdown()
                    else:
                        return self.send_json(404, {'error': 'Not found'})
                    self.send_json(200, result)
                    if self.path == '/shutdown':
                        threading.Thread(target=owner.http.shutdown, daemon=True).start()
                except Exception as error:
                    self.send_json(409, {'error': str(error)})

        LOGS.mkdir(exist_ok=True)
        self.http = http.server.ThreadingHTTPServer(('127.0.0.1', self.cfg['control_port']), Handler)
        try:
            self.start_native()
            print('LOCAL_SUPERVISOR_READY', flush=True)
            self.http.serve_forever(poll_interval=0.25)
        finally:
            if self.server is not None and self.server.poll() is None:
                self.server.stdin.write(b'shutdown\n')
                self.server.stdin.flush()
                self.server.wait(timeout=15)
            self.http.server_close()
            for handle in self.files:
                handle.close()


def gui(check_only=False, server_panel=False):
    from launcher_ui import gui as show
    return show(check_only, server_panel)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serve', action='store_true')
    parser.add_argument('--server-panel', action='store_true')
    parser.add_argument('--start-server', action='store_true')
    parser.add_argument('--status', action='store_true')
    parser.add_argument('--stop-server', action='store_true')
    parser.add_argument('--test-login', action='store_true')
    parser.add_argument('--close-test-game', action='store_true')
    parser.add_argument('--check-gui', action='store_true')
    args = parser.parse_args()
    if args.serve:
        Supervisor().run()
    elif args.start_server:
        print(json.dumps(start_server()))
    elif args.status:
        print(json.dumps(rpc('/health')))
    elif args.stop_server:
        print(json.dumps(rpc('/shutdown', {}, timeout=20)))
    elif args.test_login:
        test_script = BASE / 'isolated_login_test.py'
        if not test_script.is_file():
            raise RuntimeError('未安装隔离桌面验证脚本。')
        subprocess.run([sys.executable, str(test_script)], check=True, creationflags=NO_WINDOW)
    elif args.close_test_game:
        print(json.dumps(rpc('/close-test-game', {}, timeout=20)))
    elif args.check_gui:
        gui(check_only=True, server_panel=args.server_panel)
    else:
        gui(server_panel=args.server_panel)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        LOGS.mkdir(exist_ok=True)
        import traceback
        with (LOGS / 'launcher_errors.log').open('a', encoding='utf-8') as log:
            traceback.print_exc(file=log)
        if len(sys.argv) == 1:
            ctypes.windll.user32.MessageBoxW(None, str(error), 'CSO2 本地启动失败', 0x10)
        else:
            raise
'''

# --- launcher_ui ---
MODULE_SOURCES['launcher_ui'] = r'''"""Shared launcher/server panels with nonblocking folder discovery."""
import os
from pathlib import Path
import queue
import threading


def gui(check_only=False, server_panel=False):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    import launcher as core
    from game_paths import scan_games, validate_game
    from display_settings import PRESETS, validate, from_config
    from ui_language import UiLanguage

    cfg = core.config(); events = queue.Queue(); cancel = threading.Event()
    state = {'busy': False, 'scanning': False, 'closed': False, 'polling': False}
    root = tk.Tk()
    root.withdraw()
    root.title('CSO2 Local Master Server / 服务端' if server_panel else 'CSO2 Local Master Server')
    language=UiLanguage(root)
    root.geometry('740x825'); root.minsize(560, 420); root.resizable(True,True)
    style = ttk.Style(); style.theme_use('clam')
    style.configure('TButton', font=('Microsoft YaHei UI', 10), padding=7)
    style.configure('TLabel', font=('Microsoft YaHei UI', 10))
    surface=ttk.Frame(root);surface.pack(fill='both',expand=True)
    scroll=tk.Canvas(surface,highlightthickness=0);bar=ttk.Scrollbar(surface,orient='vertical',command=scroll.yview)
    scroll.configure(yscrollcommand=bar.set);bar.pack(side='right',fill='y');scroll.pack(side='left',fill='both',expand=True)
    panel=ttk.Frame(scroll,padding=22);item=scroll.create_window((0,0),window=panel,anchor='nw')
    panel.bind('<Configure>',lambda event:scroll.configure(scrollregion=scroll.bbox('all')))
    def resized(event):
        scroll.itemconfigure(item,width=event.width)
        for widget in panel.winfo_children():
            if isinstance(widget,ttk.Label):widget.configure(wraplength=max(300,event.width-48))
    scroll.bind('<Configure>',resized)
    def wheel(event):
        if event.widget.winfo_toplevel()==root:scroll.yview_scroll(-int(event.delta/120),'units')
    root.bind('<MouseWheel>',wheel)
    heading=ttk.Frame(panel);heading.pack(fill='x')
    ttk.Label(heading, text='CSO2 / 本地服务端' if server_panel else 'CSO2 / 本地游戏',
              font=('Microsoft YaHei UI', 21, 'bold')).pack(side='left')
    language.button(heading).pack(side='left',padx=(22,0))
    ttk.Label(panel, text='本地账号自动登录 · 窗口大小与显示方式可自定义').pack(anchor='w', pady=(5, 10))
    display=from_config(cfg)
    width_var=tk.StringVar(value=str(display['width']));height_var=tk.StringVar(value=str(display['height']))
    fullscreen_var=tk.BooleanVar(value=not display['windowed'])
    preset_var=tk.StringVar(value=f"{display['width']} × {display['height']}")
    if preset_var.get() not in PRESETS:preset_var.set('自定义')
    video=ttk.LabelFrame(panel,text='游戏分辨率',padding=8);video.pack(fill='x',pady=(0,10))
    video_row=ttk.Frame(video);video_row.pack(fill='x')
    preset=ttk.Combobox(video_row,state='readonly',values=PRESETS,textvariable=preset_var,width=18)
    preset.pack(side='left')
    ttk.Checkbutton(video_row,text='全屏',variable=fullscreen_var).pack(side='left',padx=12)
    dimensions=ttk.Frame(video);dimensions.pack(fill='x',pady=(6,0))
    ttk.Label(dimensions,text='宽度').pack(side='left');width_entry=ttk.Entry(dimensions,textvariable=width_var,width=7);width_entry.pack(side='left',padx=(5,10))
    ttk.Label(dimensions,text='高度').pack(side='left');height_entry=ttk.Entry(dimensions,textvariable=height_var,width=7);height_entry.pack(side='left',padx=5)
    save_video=ttk.Button(dimensions,text='保存显示设置');save_video.pack(side='left',padx=8)
    ttk.Label(video,text='下次启动游戏生效；不勾选全屏即为有边框窗口。').pack(anchor='w',pady=(4,0))
    low_memory_var=tk.BooleanVar(value=bool(cfg.get('low_memory',False)))
    low_memory_button=ttk.Checkbutton(video,text='低内存画质（下次启动游戏生效）',variable=low_memory_var)
    low_memory_button.pack(anchor='w',pady=(8,0))
    ttk.Label(video,text='降低纹理、关闭抗锯齿与部分特效，减少内存占用；取消后下次启动恢复。',wraplength=620).pack(anchor='w')
    memory_status=tk.StringVar(value='正在读取游戏地址空间…')
    memory_label=ttk.Label(video,textvariable=memory_status,wraplength=620)
    memory_label.pack(anchor='w',pady=(5,0))
    def choose_preset(_=None):
        if language.source(preset_var.get())!='自定义':
            w,h=preset_var.get().split(' × ');width_var.set(w);height_var.set(h)
    preset.bind('<<ComboboxSelected>>',choose_preset)
    def edited(_=None):
        value=f'{width_var.get()} × {height_var.get()}'
        preset_var.set(value if value in PRESETS else language.t('自定义'))
    width_entry.bind('<KeyRelease>',edited);height_entry.bind('<KeyRelease>',edited)
    path_var = tk.StringVar(value=cfg.get('game_root', ''))
    status = tk.StringVar(value='正在检查服务状态…')
    scan_status = tk.StringVar(value='可选择游戏目录、Bin 目录，或包含游戏的上层文件夹。')
    ttk.Label(panel, text='本地 CSO2 路径').pack(anchor='w')
    ttk.Entry(panel, textvariable=path_var, state='readonly').pack(fill='x', pady=5)
    row = ttk.Frame(panel); row.pack(fill='x')
    path_button = ttk.Button(row, text='选择文件夹并扫描')
    path_button.pack(side='left')
    ttk.Button(row, text='取消扫描', command=cancel.set).pack(side='left', padx=8)
    ttk.Label(panel, textvariable=scan_status, wraplength=640).pack(anchor='w', pady=(5, 10))
    candidates = ttk.Combobox(panel, state='readonly'); candidates.pack(fill='x')
    rule_var = tk.BooleanVar(value=cfg.get('rules', {}).get('protect_human_selection', False))
    rule_button = ttk.Checkbutton(panel, text='不把我随机选成僵尸 / 恶灵（仅 BOT 参与初始选择）', variable=rule_var)
    rule_button.pack(anchor='w', pady=(16, 5))
    instant_var=tk.BooleanVar(value=cfg.get('rules',{}).get('instant_start',True))
    instant_button=ttk.Checkbutton(panel,text='开地图不用等五秒',variable=instant_var)
    instant_button.pack(anchor='w',pady=(0,5))
    cheats_var=tk.BooleanVar(value=cfg.get('rules',{}).get('sv_cheats',False))
    cheats_button=ttk.Checkbutton(panel,text='开启作弊功能（sv_cheats）',variable=cheats_var)
    cheats_button.pack(anchor='w',pady=(0,5))
    ttk.Label(panel,text='进入本地对局后自动应用；取消勾选关闭。房主工具使用同一设置。',wraplength=640).pack(anchor='w',pady=(0,5))
    cheats_status=tk.StringVar(value='尚未指定作弊设置；勾选后开启，取消后关闭。' if 'sv_cheats' not in cfg.get('rules',{}) else '等待本地服务器与游戏状态…')
    ttk.Label(panel,textvariable=cheats_status,wraplength=640).pack(anchor='w',pady=(0,5))
    ttk.Label(panel, text='生化、恶灵附身：更改后下次加载地图生效；被攻击感染规则保留。',
              wraplength=640).pack(anchor='w')
    ttk.Separator(panel).pack(fill='x', pady=14)
    ttk.Label(panel, textvariable=status, wraplength=640).pack(anchor='w')
    ttk.Label(panel, text='本地账号：' + cfg['account']['username'] + '    密码已保存').pack(anchor='w', pady=5)
    actions = ttk.Frame(panel); actions.pack(fill='x', pady=10)

    def background(action, done=None):
        if state['busy'] or state['scanning']:
            return
        state['busy'] = True; status.set('正在处理…')
        def run():
            try:
                result = action(); events.put(('done', (done, result)))
            except Exception as exc:
                events.put(('error', str(exc)))
            finally:
                events.put(('idle', None))
        threading.Thread(target=run, daemon=True).start()

    def save_path(path):
        game = validate_game(path)
        if not game:
            raise RuntimeError('目录缺少可用的 Bin 客户端文件或 Data 资源目录。')
        fresh = core.config(); fresh['game_root'] = str(game)
        # Apply the currently stored rule to the selected client before recording it.
        from server_rules import apply_rule
        apply_rule(game, fresh.get('rules', {}).get('protect_human_selection', False))
        core.atomic_json(core.CONFIG_PATH, fresh)
        cfg.clear(); cfg.update(fresh)
        return str(game)

    def path_saved(path):
        path_var.set(path); scan_status.set('已找到并保存。服务运行中更换路径将在重启服务后使用。')

    def select_result(_=None):
        selected = candidates.get()
        if selected:
            background(lambda: save_path(selected), path_saved)
    candidates.bind('<<ComboboxSelected>>', select_result)

    def browse():
        if state['busy'] or state['scanning']:
            return
        selected = filedialog.askdirectory(parent=root, title=language.t('选择文件夹，自动扫描本地 CSO2'),
                                           initialdir=path_var.get() if Path(path_var.get()).is_dir() else str(Path.home() / 'Desktop'))
        if not selected:
            return
        cancel.clear(); state['scanning'] = True; path_button.config(state='disabled')
        scan_status.set('正在扫描…'); candidates.set(''); candidates['values'] = ()
        def scan():
            try:
                result = scan_games(selected, cancel, lambda count, n: events.put(('progress', (count, n))))
                events.put(('scan', result))
            except Exception as exc:
                events.put(('scan_error', str(exc)))
        threading.Thread(target=scan, daemon=True).start()
    path_button.config(command=browse)

    def save_rule():
        selected = bool(rule_var.get())
        def action():
            from server_rules import apply_rule
            fresh = core.config(); game = validate_game(fresh.get('game_root', ''))
            if not game:
                raise RuntimeError('请先选择文件夹并找到完整的 CSO2 客户端。')
            result = apply_rule(game, selected)
            fresh.setdefault('rules', {})['protect_human_selection'] = selected
            core.atomic_json(core.CONFIG_PATH, fresh)
            cfg.clear(); cfg.update(fresh)
            return result
        if state['busy'] or state['scanning']:
            rule_var.set(cfg.get('rules', {}).get('protect_human_selection', False)); return
        background(action, lambda result: status.set('规则已保存；下次加载地图生效。'))
    rule_button.config(command=save_rule)

    def save_instant():
        if state['busy'] or state['scanning']:
            instant_var.set(core.config().get('rules',{}).get('instant_start',True));return
        selected=bool(instant_var.get())
        def action():
            fresh=core.config();fresh.setdefault('rules',{})['instant_start']=selected
            core.atomic_json(core.CONFIG_PATH,fresh);cfg.clear();cfg.update(fresh)
        background(action,lambda result:status.set('开局等待设置已保存。新版服务下次开图生效；旧服务需退出对局后重启。'))
    instant_button.config(command=save_instant)

    def save_cheats():
        if state['busy'] or state['scanning']:
            cheats_var.set(core.config().get('rules',{}).get('sv_cheats',False));return
        selected=bool(cheats_var.get())
        def action():
            from cheat_settings import save_enabled
            result=save_enabled(selected);fresh=core.config();cfg.clear();cfg.update(fresh)
            return result
        background(action,lambda result:status.set('作弊设置已保存；本地对局就绪后自动应用并核对。' if result['monitor_requested'] else '作弊设置已保存；下次从本目录启动服务后自动应用。'))
    cheats_button.config(command=save_cheats)


    def save_low_memory():
        if state['busy'] or state['scanning']:
            low_memory_var.set(bool(core.config().get('low_memory',False)));return
        selected=bool(low_memory_var.get())
        def action():
            fresh=core.config();fresh['low_memory']=selected
            core.atomic_json(core.CONFIG_PATH,fresh);cfg.clear();cfg.update(fresh)
        background(action,lambda _:status.set('低内存画质已保存；下次启动游戏生效。当前对局画质保持原值。'))
    low_memory_button.config(command=save_low_memory)

    def video_input():return validate(width_var.get(),height_var.get(),fullscreen_var.get())
    def persist_video(value):
        fresh=core.config();fresh.update(value);core.atomic_json(core.CONFIG_PATH,fresh)
        cfg.clear();cfg.update(fresh)
    def save_display():
        try:value=video_input()
        except ValueError as exc:
            messagebox.showerror(language.t('显示设置'),language.t(str(exc)),parent=root);return
        background(lambda:persist_video(value),lambda result:status.set('显示设置已保存，下次启动游戏生效。'))
    save_video.config(command=save_display)

    def launch():
        current=core.start_server()
        if not current.get('settings_api'):
            raise RuntimeError('当前运行的是旧后台。请退出游戏后停止服务，再从此入口启动，以使用新的显示设置。')
        if current.get('game_pid'):
            raise RuntimeError('本地游戏已经运行，请先退出当前游戏。')
        if not current.get('client_cache_patch_api'):
            from client_cache_patch import before_launch as apply_client_cache_patch
            apply_client_cache_patch(core.config()['game_root'])
        if not current.get('memory_settings_api'):
            # The retained older supervisor cannot apply the new launch option.
            from memory_settings import apply as apply_memory_settings
            apply_memory_settings(bool(core.config().get('low_memory',False)),core.BASE)
        result=core.rpc('/launch', {'silent': False}, timeout=10)
        from client_diagnostics import start as start_diagnostics
        start_diagnostics(result.get('game_pid'),core.config()['game_root'])
        return result
    def start_game():
        try:value=video_input()
        except ValueError as exc:
            messagebox.showerror(language.t('显示设置'),language.t(str(exc)),parent=root);return
        def action():persist_video(value);return launch()
        background(action)
    ttk.Button(actions, text='启动本地服务' if server_panel else '启动游戏',
               command=(lambda:background(core.start_server)) if server_panel else start_game).pack(side='left', expand=True, fill='x', padx=(0, 8))
    ttk.Button(actions, text='启动游戏' if server_panel else '启动本地服务',
               command=start_game if server_panel else (lambda:background(core.start_server))).pack(side='left', expand=True, fill='x')
    row = ttk.Frame(panel); row.pack(fill='x')
    ttk.Button(row, text='保存当前存档', command=lambda: background(lambda: core.rpc('/save', {}))).pack(side='left')
    ttk.Button(row, text='停止服务并保存', command=lambda: background(lambda: core.rpc('/shutdown', {}, timeout=20))).pack(side='left', padx=8)
    def open_logs():
        core.LOGS.mkdir(exist_ok=True); os.startfile(str(core.LOGS))
    ttk.Button(row, text='查看日志', command=open_logs).pack(side='left')
    from bundle_tools import open_server_panel, restore_client_patch, restore_reshade
    utilities = ttk.Menubutton(row, text='工具 / Tools')
    utilities.pack(side='left', padx=8)
    tools_menu = tk.Menu(utilities, tearoff=False)
    utilities.configure(menu=tools_menu)
    tools_menu.add_command(label='服务端面板 / Server panel',
                           command=lambda: background(open_server_panel))
    def restore_done(message):
        messagebox.showinfo('恢复 / Restore', message, parent=root)
    tools_menu.add_separator()
    tools_menu.add_command(label='还原模型加载补丁 / Restore model patch',
                           command=lambda: background(restore_client_patch, restore_done))
    tools_menu.add_command(label='恢复 ReShade / Restore ReShade',
                           command=lambda: background(restore_reshade, restore_done))
    def solo():
        from local_modes import show_solo_dialog
        try:
            show_solo_dialog(root, core.config(), core.rpc, background)
        except Exception as exc:
            messagebox.showerror(language.t('单人开图'),language.t(str(exc)), parent=root)
    ttk.Button(panel, text='单人开图 · 选择模式与地图', command=solo).pack(fill='x', pady=12)
    ttk.Label(panel, text='关闭面板后服务继续运行。已有对局运行时不会自动重启服务。', wraplength=640).pack(anchor='w')

    def poll():
        if not state['busy'] and not state['polling']:
            state['polling'] = True
            def run():
                try:
                    health=core.rpc('/health', timeout=.5)
                    from memory_pressure import probe
                    health['memory_pressure']=probe(health.get('game_pid'),health.get('game_root'))
                    events.put(('health',health))
                except Exception:
                    events.put(('health', None))
            threading.Thread(target=run, daemon=True).start()
        root.after(4000, poll)

    def drain():
        while True:
            try:
                kind, value = events.get_nowait()
            except queue.Empty:
                break
            if kind == 'progress':
                scan_status.set(f'已扫描 {value[0]} 个文件夹，发现 {value[1]} 份客户端…')
            elif kind in ('scan', 'scan_error'):
                state['scanning'] = False; path_button.config(state='normal')
                if kind == 'scan_error':
                    scan_status.set(value); continue
                if value['cancelled']:
                    scan_status.set('扫描已取消，原路径保留。'); continue
                paths = value['paths']; candidates['values'] = paths
                if len(paths) == 1:
                    candidates.current(0); background(lambda p=paths[0]: save_path(p), path_saved)
                elif paths:
                    scan_status.set(f'找到 {len(paths)} 份客户端，请在列表中选择。')
                else:
                    scan_status.set(f'未找到完整客户端；扫描 {value["visited"]} 个文件夹，跳过 {value["skipped"]} 个不可读目录。')
            elif kind == 'done':
                if value[0]:
                    value[0](value[1])
            elif kind == 'error':
                rule_var.set(core.config().get('rules', {}).get('protect_human_selection', False))
                instant_var.set(core.config().get('rules', {}).get('instant_start',True))
                cheats_var.set(core.config().get('rules', {}).get('sv_cheats',False))
                low_memory_var.set(bool(core.config().get('low_memory',False)))
                status.set(value); messagebox.showerror(language.t('CSO2 / 本地游戏'),language.t(value), parent=root)
            elif kind == 'idle':
                state['busy'] = False
            elif kind == 'health':
                state['polling'] = False
                pressure=(value or {}).get('memory_pressure',{'level':'unknown','message':'未取得游戏内存状态。'})
                memory_status.set(pressure['message'])
                memory_label.configure(foreground={'critical':'#b42424','low':'#8a5500'}.get(pressure['level'],'#333333'))
                if not state['busy']:
                    low_memory_var.set(bool(core.config().get('low_memory',False)))
                    cheats_var.set(core.config().get('rules',{}).get('sv_cheats',False))
                    try:
                        import json
                        from cheat_settings import status_message
                        actual=json.loads((core.BASE/'sv_cheats_state.json').read_text(encoding='utf-8'))
                        cheats_status.set(status_message(actual,value,core.config(),core.BASE))
                    except (OSError,ValueError,KeyError):
                        cheats_status.set('未指定作弊设置，保持游戏原值。' if 'sv_cheats' not in core.config().get('rules',{}) else '作弊设置已保存；等待对局应用。')
                    if value and value['ready']:
                        moved = (value.get('base') and Path(value['base']).resolve() != core.BASE) or (not value.get('base') and core.config().get('migration_source'))
                        status.set('原目录服务仍运行；当前对局结束后停止服务，再从这里启动。' if moved else
                                   ('本地服务已就绪 · 游戏运行中' if value.get('game_pid') else '本地服务已就绪'))
                    else:
                        status.set('本地服务未启动')
        root.after(60, drain)

    def close():
        state['closed'] = True; cancel.set(); root.destroy()
    root.protocol('WM_DELETE_WINDOW', close)
    language.capture(root);language.refresh()
    if check_only:
        root.update_idletasks(); size = (panel.winfo_reqwidth(), panel.winfo_reqheight())
        if size[0]>700:raise RuntimeError(f'GUI content too wide: {size}')
        root.destroy()
        print({'gui': 'server' if server_panel else 'launcher', 'fits': True, 'content': size,'scrollable':True,'resizable':True})
        return
    from local_update import ReleaseUpdater
    updater = ReleaseUpdater(root, close, state, language, UPDATE_STARTUP_TICKET, UPDATE_SKIP_ONCE)
    tools_menu.add_separator()
    tools_menu.add_command(label='检查更新 / Check updates', command=lambda: updater.check(manual=True))
    tools_menu.add_command(label='手动更新 / Open Release', command=updater.open_release)
    root.deiconify();root.after(50, drain); root.after(100, poll); root.mainloop()
'''

# --- local_modes ---
MODULE_SOURCES['local_modes'] = r'''"""Local mode catalog, solo room command, and launcher dialog."""
from __future__ import annotations
import csv
import io
from pathlib import Path
import re
import secrets
import time


def mode_catalog(root):
    custom = Path(root) / 'custom'
    scripts = custom / 'scripts'
    # These two tables contain mixed-encoding comments. Data columns used here
    # are ASCII; Latin-1 keeps every source byte intact.
    def rows(name):
        return [r for r in csv.reader(io.StringIO((scripts / name).read_bytes().decode('latin1')))
                if len(r) > 3 and r[1].isdigit()]
    names = {k.lower(): v for k, v in re.findall(r'^\s*"([^"\r\n]+)"\s+"([^"\r\n]*)"',
             (custom / 'resource/cso2_schinese.txt').read_text(encoding='utf-16'), re.MULTILINE)}
    maps = {int(r[1]): {'id': int(r[1]), 'name': r[0]} for r in rows('cso2_maplist.csv') if r[3] == '1'}
    modes = []
    for r in rows('cso2_modlist.csv'):
        if r[3] != '1':
            continue
        ids = list(dict.fromkeys(int(x) for x in r[32].split('/') if x.isdigit() and int(x) in maps))
        modes.append({'id': int(r[1]), 'name': r[0], 'display_name': names.get('cso2_mod_name_' + r[0].lower(), r[0]),
                      'maps': [maps[i] for i in ids], 'bots': int(r[13]), 'min_player_rule': int(r[17])})
    return modes


def request_solo_room(owner, mode_id, map_id):
    mode_id, map_id = int(mode_id), int(map_id)
    mode = next((m for m in mode_catalog(owner.cfg['game_root']) if m['id'] == mode_id), None)
    if mode is None or map_id not in {m['id'] for m in mode['maps']}:
        raise ValueError('模式或地图不在当前晴雪客户端列表内。')
    with owner.lock:
        if not owner.status()['ready']:
            raise RuntimeError('请先启动本地服务并登录游戏。')
        log = owner.logs / 'server.log'
        offset = log.stat().st_size
        token = secrets.token_hex(8)
        owner.server.stdin.write(f'solo-start {token} {mode_id} {map_id}\n'.encode('ascii'))
        owner.server.stdin.flush()
        marker = 'LOCAL_SOLO_RESULT ' + token + ' '
        for _ in range(80):
            with log.open('rb') as f:
                f.seek(offset)
                text = f.read().decode('utf-8', errors='replace')
            line = next((line for line in text.splitlines() if marker in line), None)
            if line is not None:
                result = line.split(marker, 1)[1].strip()
                if result != 'ok':
                    errors = {'login_required': '请先启动游戏并等到账号进入大厅。',
                              'leave_current_room_first': '请先退出当前房间，再选择单人开图。'}
                    raise RuntimeError(errors.get(result, '单人开图请求失败，请查看服务日志。'))
                return {'requested': True, 'mode_id': mode_id, 'map_id': map_id}
            time.sleep(.1)
        raise RuntimeError('等待服务端开图回复超时，请查看日志。')


def show_solo_dialog(parent, cfg, rpc, work):
    import tkinter as tk
    from tkinter import messagebox, ttk
    modes = mode_catalog(cfg['game_root'])
    language=getattr(parent,'ui_language',None)
    t=language.t if language else str
    win = tk.Toplevel(parent)
    win.withdraw();win.title(t('CSO2 单人开图'))
    win.geometry('540x285')
    win.resizable(False, False)
    box = ttk.Frame(win, padding=20)
    box.pack(fill='both', expand=True)
    ttk.Label(box, text='先登录游戏进入大厅；退出当前房间后可直接开图。').pack(anchor='w', pady=(0, 12))
    mode_choice = ttk.Combobox(box, state='readonly', values=[f"{m['display_name'] if not language or language.lang=='zh' else m['name']}  [ID {m['id']}]" for m in modes])
    mode_choice.pack(fill='x', pady=6)
    map_choice = ttk.Combobox(box, state='readonly')
    map_choice.pack(fill='x', pady=6)
    def changed(_=None):
        selected = modes[mode_choice.current()]['maps']
        map_choice['values'] = [f"{m['name']}  [ID {m['id']}]" for m in selected]
        if selected:
            map_choice.current(0)
    mode_choice.bind('<<ComboboxSelected>>', changed)
    mode_choice.current(0)
    changed()
    ttk.Label(box, text='允许单人开始；默认 CT 3 名、TR 4 名人机。\n人机数量和难度也可在游戏房间设置中调整。').pack(anchor='w', pady=10)
    def start():
        mode = modes[mode_choice.current()]
        if map_choice.current() < 0:
            messagebox.showerror(t('单人开图'),t('该模式没有可选地图。'), parent=win)
            return
        map_id = mode['maps'][map_choice.current()]['id']
        work(lambda: rpc('/solo-room', {'mode_id': mode['id'], 'map_id': map_id}, timeout=12))
        win.destroy()
    ttk.Button(box, text='进入所选地图', command=start).pack(fill='x')
    if language:
        win.title(language.t('CSO2 单人开图'));language.capture(win);language.refresh()
    win.deiconify()
'''

# --- memory_pressure ---
MODULE_SOURCES['memory_pressure'] = r'''"""Read-only process address-space status and native fatal-error diagnosis."""
import ctypes as C
import re


def classify(sample):
    free=float(sample['address_free_mb']); largest=float(sample['largest_free_mb'])
    # Heuristics, not allocation guarantees. A fresh map can consume hundreds of MB.
    if free<128 or largest<8:return 'critical'
    if free<512 or largest<64:return 'low'
    return 'normal'


def describe(sample):
    level=classify(sample)
    detail=f"地址空间剩余 {sample['address_free_mb']:.0f} MB · 最大连续空块 {sample['largest_free_mb']:.0f} MB"
    if level=='critical':return detail+'。空间严重不足，继续加载模型可能退出；建议退出游戏后重新启动。'
    if level=='low':return detail+'。空间偏紧，换图或换装可能耗尽；可在下次启动前开启低内存画质。'
    return detail+'（仅当前采样，不能保证下一次加载成功）。'


def probe(pid, expected_root=None):
    if not pid:return {'level':'idle','message':'游戏未运行。'}
    from pathlib import Path
    from client_diagnostics import kernel,memory,modules
    k=kernel();handle=k.OpenProcess(0x410,False,int(pid))
    if not handle:return {'level':'unknown','message':'暂时无法读取游戏内存状态。'}
    try:
        if expected_root is not None:
            mods=modules(k,int(pid))
            entry=mods.get('counterstrikeonline2.exe')
            if entry is None or entry[1].parent.resolve()!=(Path(expected_root)/'Bin').resolve():
                return {'level':'unknown','message':'游戏进程已变化，等待重新读取状态。'}
        sample=memory(k,handle)
        return {'level':classify(sample),'message':describe(sample),'sample':sample}
    except (OSError,ValueError,KeyError):
        return {'level':'unknown','message':'暂时无法读取游戏内存状态。'}
    finally:k.CloseHandle(handle)


def fatal_diagnosis(text):
    # Match the engine's exact error. A high footprint alone does not prove OOM.
    match=re.search(r'CMDLCache:: Out of memory \[Type:(\d+) \((\d+)\)\]',text)
    if not match:return None
    kind,size=map(int,match.groups())
    return {'reason':'model_cache_out_of_memory','cache_type':kind,'allocation_bytes':size,
            'message':f'游戏模型缓存申请 {size/1048576:.2f} MB 失败并退出。可先重启客户端，再尝试低内存画质；仅凭此错误不能认定角色文件损坏。'}
'''

# --- memory_settings ---
MODULE_SOURCES['memory_settings'] = r'''"""Opt-in graphics memory reduction. Applied only before a new client starts."""
import json
import os
from pathlib import Path
import winreg

KEY=r'Software\Nexon\cso2\Settings'
VALUES={'mat_picmip':2,'ScreenMSAA':0,'ScreenMSAAQuality':0,'mat_antialias':0,
        'mat_aaquality':0,'ShadowDepthTexture':0,'mat_cso2shadowlevel':1,
        'mat_viewmodelshadow':0,'mat_cso2ao':0,'MotionBlur':0}


def _snapshot(key, name):
    try:
        value, kind=winreg.QueryValueEx(key,name)
        return {'exists':True,'value':value,'type':kind}
    except FileNotFoundError:
        return {'exists':False}


def _restore(key, name, entry):
    if entry['exists']:
        winreg.SetValueEx(key,name,0,entry['type'],entry['value'])
    else:
        try:winreg.DeleteValue(key,name)
        except FileNotFoundError:pass


def _save(path,data):
    tmp=path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    os.replace(tmp,path)


def apply(enabled,folder):
    """Keep a per-enable-cycle lease; a disabled default never writes settings.

    The historical memory_settings_backup.json is deliberately not consumed: it
    cannot prove that this option currently owns the user's graphics values.
    Values edited by the game/user while enabled are not overwritten on disable.
    """
    state_path=Path(folder)/'memory_settings_active.json'
    state=None
    if state_path.exists():
        state=json.loads(state_path.read_text(encoding='utf-8'))
        if (state.get('version')!=1 or state.get('key')!=KEY
                or set(state.get('values',{}))!=set(VALUES)):
            raise RuntimeError('低内存设置恢复记录无效；未修改画质，请检查 memory_settings_active.json。')
        for name,entry in state['values'].items():
            if (not isinstance(entry,dict) or type(entry.get('exists')) is not bool
                    or (entry['exists'] and ('type' not in entry or 'value' not in entry))):
                raise RuntimeError('低内存设置恢复记录不完整；未修改画质。')
    if not enabled and state is None:
        return {'enabled':False,'changed':False}
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,KEY,0,winreg.KEY_READ|winreg.KEY_WRITE) as key:
        if enabled:
            if state is None:
                state={'version':1,'key':KEY,'values':{n:_snapshot(key,n) for n in VALUES}}
                _save(state_path,state)  # Persist originals before any registry mutation.
            try:
                for name,value in VALUES.items():
                    winreg.SetValueEx(key,name,0,winreg.REG_DWORD,value)
                if not all(winreg.QueryValueEx(key,n)==(v,winreg.REG_DWORD) for n,v in VALUES.items()):
                    raise RuntimeError('低内存画质保存校验失败')
            except Exception:
                # Keep the journal on any failure so restoration can be retried.
                for name,entry in state['values'].items():
                    if _snapshot(key,name)=={'exists':True,'value':VALUES[name],'type':winreg.REG_DWORD}:
                        _restore(key,name,entry)
                raise
        else:
            for name,entry in state['values'].items():
                if _snapshot(key,name)=={'exists':True,'value':VALUES[name],'type':winreg.REG_DWORD}:
                    _restore(key,name,entry)
                    if _snapshot(key,name)!=entry:
                        raise RuntimeError('低内存画质恢复校验失败：'+name)
            state_path.unlink()
    return {'enabled':bool(enabled),'changed':True,'backup':str(state_path)}
'''

# --- pkg_assets ---
MODULE_SOURCES['pkg_assets'] = r'''"""Read local CSO2 PKG resources using Windows CNG; no client process needed.

Format reference: https://github.com/lateleite/libuncso2 (PKG structures and tests).
This is an independent Python reader. It never alters a package.
"""
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct

ENTRY_KEYS=[b'lkgui781kl789sd!@#%89&^sd',bytes.fromhex('9b65c79bc7df8e7ed4c659525cf722fff4e8ffe7b5c277'),bytes.fromhex('863953bd16116d062a84f34ee04aa3')]
DATA_KEYS=[b'^9gErg2Sx7bnk7@#sdfjnh@',bytes.fromhex('8e5cb89245d190ba820fd97a998eb387f7'),bytes.fromhex('1f9ff8f418ac25a2bb37826da8aea728badddde46b')]

class AES:
    def __init__(self,key):
        self.lib=C.WinDLL('bcrypt');p=C.c_void_p;u=C.c_ulong
        signatures={
            'BCryptOpenAlgorithmProvider':([C.POINTER(p),C.c_wchar_p,C.c_wchar_p,u],C.c_long),
            'BCryptSetProperty':([p,C.c_wchar_p,p,u,u],C.c_long),
            'BCryptGenerateSymmetricKey':([p,C.POINTER(p),p,u,p,u,u],C.c_long),
            'BCryptDecrypt':([p,p,u,p,p,u,p,u,C.POINTER(u),u],C.c_long),
            'BCryptDestroyKey':([p],C.c_long),
            'BCryptCloseAlgorithmProvider':([p,u],C.c_long),
        }
        for n,(args,res) in signatures.items():getattr(self.lib,n).argtypes=args;getattr(self.lib,n).restype=res
        self.provider=p();self.handle=p()
        self.check(self.lib.BCryptOpenAlgorithmProvider(C.byref(self.provider),'AES',None,0))
        mode=C.create_unicode_buffer('ChainingModeCBC')
        self.check(self.lib.BCryptSetProperty(self.provider,'ChainingMode',mode,C.sizeof(mode),0))
        secret=C.create_string_buffer(key)
        self.check(self.lib.BCryptGenerateSymmetricKey(self.provider,C.byref(self.handle),None,0,secret,len(key),0))
    @staticmethod
    def check(status):
        if status<0:raise OSError(f'Windows AES error 0x{status&0xffffffff:08x}')
    def decrypt(self,data):
        if len(data)%16:raise ValueError('AES data not aligned')
        src=C.create_string_buffer(data);dst=C.create_string_buffer(len(data));iv=C.create_string_buffer(16);n=C.c_ulong()
        self.check(self.lib.BCryptDecrypt(self.handle,src,len(data),None,iv,16,dst,len(data),C.byref(n),0))
        assert n.value==len(data)
        return dst.raw
    def close(self):
        if self.handle:self.lib.BCryptDestroyKey(self.handle);self.handle=None
        if self.provider:self.lib.BCryptCloseAlgorithmProvider(self.provider,0);self.provider=None
    def __enter__(self):return self
    def __exit__(self,*_):self.close()

def key_for(secret,name):return hashlib.md5(secret+name.encode('ascii')).hexdigest()[:16].encode('ascii')

def read_header(path):
    with path.open('rb') as f:
        f.seek(33);block=f.read(272)
        if len(block)!=272:raise ValueError('Not a PKG data archive')
        for region,secret in enumerate(ENTRY_KEYS):
            with AES(key_for(secret,path.name)) as cipher:
                data=cipher.decrypt(block)
                zero,count=struct.unpack_from('<II',data,261)
                if zero or count>100000 or 305+count*288>path.stat().st_size:continue
                directory=data[:261].split(b'\0')[0].decode('utf-8',errors='replace')
                result=[];start=305+count*288
                for _ in range(count):
                    record=cipher.decrypt(f.read(288))
                    name=record[:261].split(b'\0')[0].decode('utf-8')
                    off,enc,dec=struct.unpack_from('<III',record,261)
                    if off+enc+start>path.stat().st_size or dec>enc:raise ValueError('PKG entry out of bounds')
                    result.append({'name':name.replace('\\','/').lstrip('/'),'package':path.name,'offset':start+off,'stored':enc,'size':dec,'encrypted':bool(record[274]),'region':region})
                return directory,result
        raise ValueError('No known package key matched')

def build_index(root):
    entries={};failures=[];duplicates=[];packages=0
    for path in sorted((Path(root)/'Data').glob('*.pkg')):
        try:directory,records=read_header(path)
        except (OSError,ValueError,UnicodeError) as e:
            failures.append({'package':path.name,'error':str(e)});continue
        packages+=1
        for record in records:
            name=record['name'].lower()
            if name in entries:duplicates.append(name)
            entries[name]=record
    return {'packages':packages,'entries':entries,'failures':failures,'duplicates':duplicates}

def extract(root,entry):
    with (Path(root)/'Data'/entry['package']).open('rb') as f:
        f.seek(entry['offset']);data=f.read(entry['stored'])
    if len(data)!=entry['stored']:raise ValueError('Truncated resource')
    if entry['encrypted']:
        name=entry['name'].rsplit('/',1)[-1]
        with AES(key_for(DATA_KEYS[entry['region']],name)) as cipher:
            data=b''.join(cipher.decrypt(data[i:i+65536]) for i in range(0,len(data),65536))
    return data[:entry['size']]

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('root');p.add_argument('output');args=p.parse_args()
    result=build_index(args.root)
    Path(args.output).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'packages':result['packages'],'entries':len(result['entries']),'failures':result['failures'][:6],'duplicates':len(result['duplicates'])}))
'''

# --- runtime_compat ---
MODULE_SOURCES['runtime_compat'] = r'''"""Bounded, read-only discovery and address resolution for compatible CSO2 images.

An instruction match alone cannot validate the many private entity layouts.
The mapped image layout must also match a verified family before enabling it.
"""
from pathlib import Path
import hashlib,ipaddress,json,re,struct
from functools import lru_cache


class CompatibilityError(RuntimeError):pass


def path_key(path):
    return str(Path(path).resolve()).casefold() if path else ''


def game_root(module_path):
    directory=Path(module_path).resolve().parent
    for candidate in (directory,*list(directory.parents)[:3]):
        if (candidate/'Data').is_dir():return candidate
    return directory.parent if directory.name.casefold() in ('bin','bin32','win32') else directory


def choose_candidate(candidates,preferred):
    """A selected directory disambiguates; a stale directory does not block discovery."""
    wanted=path_key(preferred) if preferred else ''
    matching=[item for item in candidates if wanted and wanted in
              (path_key(game_root(item[1]['client.dll'][2])),path_key(item[1]['client.dll'][2].parent))]
    pool=matching or candidates
    if len(pool)!=1:
        if not pool:raise CompatibilityError('未发现同时加载 client.dll 和 engine.dll 的客户端')
        details='；'.join(f'PID {pid} · {game_root(mods["client.dll"][2])}' for pid,mods in pool[:5])
        raise CompatibilityError('发现多个客户端，请选择目标游戏目录；'+details)
    return pool[0]


class PEImage:
    def __init__(self,raw):
        self.raw=raw
        def u16(at):return struct.unpack_from('<H',raw,at)[0]
        def u32(at):return struct.unpack_from('<I',raw,at)[0]
        try:
            if len(raw)<256 or raw[:2]!=b'MZ':raise ValueError('不是 PE 文件')
            nt=u32(60)
            if raw[nt:nt+4]!=b'PE\0\0':raise ValueError('PE 标头无效')
            machine,count=u16(nt+4),u16(nt+6);opt=nt+24;opt_size=u16(nt+20)
            if machine!=0x14c or u16(opt)!=0x10b:raise ValueError('当前适配器仅支持 32 位 x86 客户端')
            if not 1<=count<=96 or opt_size<224:raise ValueError('PE 节表无效')
            self.image_base=u32(opt+28);self.image_size=u32(opt+56)
            if not 4096<=self.image_size<=512*1024*1024:raise ValueError('PE 映像大小无效')
            self.sections=[]
            for index in range(count):
                at=opt+opt_size+index*40
                name=raw[at:at+8].split(b'\0')[0].decode('ascii','replace')
                size,rva,stored,offset=struct.unpack_from('<4I',raw,at+8);flags=u32(at+36)
                if offset+stored>len(raw) or rva+max(size,stored)>self.image_size:raise ValueError('PE 节越界')
                if any(rva<s['rva']+max(s['size'],s['stored']) and s['rva']<rva+max(size,stored) for s in self.sections):raise ValueError('PE 节重叠')
                self.sections.append(dict(name=name,rva=rva,size=size,stored=stored,offset=offset,flags=flags))
            # Ignore file metadata/overlay/signing differences, never code/data or layout changes.
            directories=[(i,u32(opt+96+8*i),u32(opt+100+8*i)) for i in range(min(u32(opt+92),16)) if i not in (2,4,6)]
            description=[machine,self.image_base,self.image_size,u32(opt+16),u32(opt+32),u16(opt+70),directories]
            digest=hashlib.sha256(json.dumps(description,separators=(',',':')).encode())
            for section in self.sections:
                digest.update(json.dumps(section,separators=(',',':')).encode())
                # Resource bytes are UI/version metadata, but resource section geometry still matters.
                if section['name']!='.rsrc' or section['flags']&0x20000000:
                    digest.update(raw[section['offset']:section['offset']+section['stored']])
            self.layout_hash=digest.hexdigest()
        except (ValueError,struct.error,OverflowError) as ex:raise CompatibilityError(str(ex)) from ex

    @classmethod
    def from_path(cls,path):
        path=Path(path)
        if not 256<=path.stat().st_size<=128*1024*1024:raise CompatibilityError('模块文件大小无效')
        return cls(path.read_bytes())

    def find_anchor(self,spec):
        key=json.dumps(spec,sort_keys=True)
        if key in getattr(self,'_anchor_hits',{}):return self._anchor_hits[key]
        pattern=bytes.fromhex(spec['pattern']);mask=bytes.fromhex(spec['mask'])
        if len(pattern)!=len(mask) or sum(bool(x) for x in mask)<16:raise CompatibilityError('定位特征过短')
        matcher=re.compile(b''.join(re.escape(bytes((v,))) if keep else b'.' for v,keep in zip(pattern,mask)),re.DOTALL)
        hits=[]
        for section in self.sections:
            if not section['flags']&0x20000000:continue
            data=self.raw[section['offset']:section['offset']+section['stored']]
            position=0
            while (match:=matcher.search(data,position)) is not None:
                hits.append(section['rva']+match.start())
                if len(hits)>1:raise CompatibilityError('地址特征不唯一')
                position=match.start()+1
        if not hits:raise CompatibilityError('找不到地址特征')
        if not hasattr(self,'_anchor_hits'):self._anchor_hits={}
        self._anchor_hits[key]=hits[0]
        return hits[0]

    def read_rva(self,rva,length):
        for section in self.sections:
            if section['rva']<=rva and rva+length<=section['rva']+section['stored']:
                offset=section['offset']+rva-section['rva'];return self.raw[offset:offset+length]
        raise CompatibilityError('定位指令不在文件映像中')


def resolve_module(mem,module,spec,optional_keys=()):
    base,size,path=module;image=module_image(path)
    actual_hash=hashlib.sha256(image.raw).hexdigest()
    report=dict(path=str(path),sha256=actual_hash,layout_hash=image.layout_hash,
                architecture='x86',image_size=image.image_size)
    if image.layout_hash!=spec['layout_hash']:
        error=CompatibilityError(f'{Path(path).name} 的代码或数据布局尚未适配（{actual_hash[:12]}）；已停止连接')
        error.report=report;raise error
    if size!=image.image_size or not 0x10000<=base<base+size<=0xffff0000:
        raise CompatibilityError('加载模块范围与映像不符')
    resolved={};errors={}
    for key,anchors in spec['anchors'].items():
        try:
            addresses=set()
            for anchor in anchors:
                rva=image.find_anchor(anchor);pattern=bytes.fromhex(anchor['pattern']);mask=bytes.fromhex(anchor['mask'])
                live=mem.read(base+rva,len(pattern))
                if any(keep and a!=b for a,b,keep in zip(live,pattern,mask)):raise CompatibilityError('运行中特征变化：'+key)
                pointer=struct.unpack_from('<I',live,anchor['operand'])[0]-anchor.get('delta',0)
                disk_pointer=struct.unpack('<I',image.read_rva(rva+anchor['operand'],4))[0]-anchor.get('delta',0)
                if pointer-base!=disk_pointer-image.image_base:raise CompatibilityError('运行中地址操作数被重定向：'+key)
                if not base<=pointer<base+size:raise CompatibilityError('特征目标越界：'+key)
                addresses.add(pointer)
            if len(addresses)!=1:raise CompatibilityError('多处特征定位结果冲突：'+key)
            resolved[key]=addresses.pop()
        except Exception as ex:
            if key not in optional_keys:raise
            errors[key]=str(ex)
    report['unavailable']=errors
    report.update(method='instruction_operands',resolved={k:hex(v-base) for k,v in resolved.items()})
    return resolved,report


def connection_kind(game):
    """Log is only evidence for optional local-host tools, never an attach gate.

    Do not resolve DNS: a VPS/domain must not become local due to name lookup.
    """
    root=Path(game);paths=[root/'Bin/cso2_report_log.txt',root/'cso2_report_log.txt']
    if not any(p.is_file() for p in paths) and root.is_dir():paths.extend(root.glob('*/cso2_report_log.txt'))
    existing=[]
    for path in dict.fromkeys(paths):
        try:
            stat=path.stat();existing.append((stat.st_mtime_ns,path,stat.st_size))
        except OSError:pass
    if not existing:return 'unknown'
    stamp,path,size=max(existing,key=lambda item:item[0])
    return _connection_from_log(str(path),stamp,size)


@lru_cache(maxsize=64)
def _connection_from_log(path,stamp,size):
    try:
        with Path(path).open('rb') as stream:
            stream.seek(0,2);size=stream.tell();stream.seek(max(0,size-131072));tail=stream.read()
    except OSError:return 'unknown'
    events=list(re.finditer(rb'Connect to\s+([^\r\n]+)|(?:Disconnect(?:ed|ing)?\b|Connection\s+(?:closed|failed)\b)',tail,re.I))
    if not events or events[-1].group(1) is None:return 'unknown'
    raw=events[-1].group(1).decode('ascii','replace').strip()
    match=re.fullmatch(r'(\[[^\]]+\]|[^\s]+):(\d+)\s*\.\.\.',raw)
    if not match or not 0<int(match[2])<=65535:return 'unknown'
    host=match[1].strip('[]').casefold().rstrip('.')
    if host in ('localhost','loopback'):return 'local'
    try:
        address=ipaddress.ip_address(host.split('%',1)[0])
        if isinstance(address,ipaddress.IPv6Address) and address.ipv4_mapped:address=address.ipv4_mapped
        return 'local' if address.is_loopback else 'remote'
    except ValueError:return 'remote'


FAMILY_LAYOUTS={
    'client.dll':'956fcf3b1bda3f6fbb8b025c3e68d12a81d2980b69c71b4f94db46f70489bca1',
    'engine.dll':'7f933de0f77709684092df7ceb7eb5813a621e09ac9b4b9f26cbf21ae610cdc0',
    'server.dll':'f4f60977bbf7d04010be9eec11713fc4e2e46b79386e8bad0f6e81dddb850e59',
}


def module_image(path):
    path=Path(path).resolve();stat=path.stat()
    return _cached_image(str(path),stat.st_size,stat.st_mtime_ns,stat.st_ctime_ns)


@lru_cache(maxsize=12)
def _cached_image(path,size,mtime,ctime):return PEImage.from_path(path)


def verify_family(module,name):
    base,size,path=module;image=module_image(path)
    if name not in FAMILY_LAYOUTS or image.layout_hash!=FAMILY_LAYOUTS[name]:
        raise CompatibilityError(name+' 的代码或数据布局尚未适配')
    if size!=image.image_size or not 0x10000<=base<base+size<=0xffff0000:
        raise CompatibilityError(name+' 加载范围不符')
    return image


def native_loopback(reader):
    m=reader.mem;e=reader.engine
    interface=m.u32(reader.client+0x1cdbb5c);vt=m.u32(interface)
    expected=b'\xa1'+struct.pack('<I',e+0x8d21a0)+b'\xc3'
    if m.u32(vt+81*4)!=e+0x184540 or m.read(e+0x184540,6)!=expected:
        raise CompatibilityError('网络通道入口未验证')
    channel=m.u32(e+0x8d21a0)
    if not channel:return False
    fn=m.u32(m.u32(channel)+24)
    if fn!=e+0x1251a0 or m.read(fn,13)!=bytes.fromhex('33c083b9ac000000010f94c0c3'):
        raise CompatibilityError('本地网络通道类型未验证')
    return m.u32(channel+0xac)==1


def command_entry(reader):
    m=reader.mem;e=reader.engine;c=reader.client
    command=m.u32(m.u32(m.u32(c+0x1cdbb5c))+0x20)
    expected=(b'\x80\x3d'+struct.pack('<I',e+0x912b9d)+bytes.fromhex('007425a1')+
        struct.pack('<I',e+0x754b18)+bytes.fromhex('83c0023d000800007d1f8b542404b9630000006a64e87862efff83c404c204008b4c2404e8f95fefffc20400'))
    if command!=e+0x1830b0 or m.read(command,len(expected))!=expected:
        raise CompatibilityError('游戏原生命令入口未验证')
    return command


def field_check(mem,base,checks):
    for rva,name,offset,delta in checks:
        if mem.string(mem.u32(base+rva),80)!=name or mem.u32(base+rva+delta)!=offset:
            raise CompatibilityError('字段未验证：'+name)


def probe_result(action):
    try:action();return {'available':True,'reason':''}
    except Exception as ex:return {'available':False,'reason':str(ex)}


def server_compatible(reader):
    try:verify_family(reader.mods['server.dll'],'server.dll');return True
    except Exception:return False


def current_local_server(reader,base):
    try:return reader.mods.get('server.dll',(0,))[0]==base and server_compatible(reader) and native_loopback(reader)
    except Exception:return False
'''

# --- server_rules ---
MODULE_SOURCES['server_rules'] = r'''"""Reversible, hash-checked overrides of the local host's mode bytecode."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import shutil

BASE = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.tmp')
    temp.write_bytes(data); os.replace(temp, path)


def apply_rule(root, enabled):
    root = Path(root).resolve()
    folder = root / '.local_cso2_rules'
    state_path = folder / 'state.json'
    state = json.loads(state_path.read_text(encoding='utf-8')) if state_path.exists() else {}
    manifest = json.loads((BASE / 'rules/manifest.json').read_text(encoding='utf-8'))
    if not enabled and not state:
        return {'enabled': False, 'changed': False}
    plans = []
    for mode, entry in manifest.items():
        rel = f'custom/scripts/mod/{mode}/mod_{mode}.elo'
        target = root / rel
        current = target.read_bytes() if target.exists() else None
        tracked = state.get('files', {}).get(mode)
        if enabled:
            patch = (BASE / 'rules' / f'mod_{mode}.elo').read_bytes()
            if digest(patch) != entry['patched_elo_sha256']:
                raise RuntimeError('规则包校验失败：' + mode)
            if tracked and current is not None and digest(current) == tracked['patched_hash']:
                continue
            if tracked:
                raise RuntimeError('规则脚本被其他程序更改，未覆盖：' + str(target))
            if current is not None:
                original = current
            else:
                loose = root / 'Data/cstrike/scripts/mod' / mode / f'mod_{mode}.elo'
                if loose.exists():
                    original = loose.read_bytes()
                else:
                    from pkg_assets import extract
                    original = extract(root, entry['package_entry'])
            if digest(original) != entry['original_elo_sha256']:
                raise RuntimeError('所选客户端的模式脚本版本不同，未修改：' + mode)
            plans.append((mode, target, current, patch))
        elif tracked:
            if current is None or digest(current) != tracked['patched_hash']:
                raise RuntimeError('规则脚本已被更改，不能自动还原：' + str(target))
            backup = tracked.get('backup')
            restored = (folder / backup).read_bytes() if backup else None
            if restored is not None and digest(restored) != tracked['original_hash']:
                raise RuntimeError('原始备份校验失败：' + mode)
            plans.append((mode, target, current, restored))
    if not plans:
        return {'enabled': bool(enabled), 'changed': False}
    before = state_path.read_bytes() if state_path.exists() else None
    state.setdefault('files', {})
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    if enabled:
        for mode, target, current, patch in plans:
            backup = f'backups/{stamp}/mod_{mode}.elo' if current is not None else None
            if backup:
                atomic(folder / backup, current)
            state['files'][mode] = {'backup': backup,
                'original_hash': digest(current) if current is not None else None,
                'patched_hash': digest(patch)}
    changed = []
    try:
        for mode, target, current, data in plans:
            if data is None:
                target.unlink()
            else:
                atomic(target, data)
            changed.append((target, current))
            if not enabled:
                state['files'].pop(mode, None)
        if state['files']:
            state['enabled'] = bool(enabled)
            atomic(state_path, json.dumps(state, ensure_ascii=False, indent=2).encode('utf-8'))
        elif state_path.exists():
            state_path.unlink()
    except Exception:
        for target, original in reversed(changed):
            if original is None:
                target.unlink(missing_ok=True)
            else:
                atomic(target, original)
        if before is not None:
            atomic(state_path, before)
        raise
    return {'enabled': bool(enabled), 'changed': True, 'modes': [x[0] for x in plans]}
'''

# --- server_updates ---
MODULE_SOURCES['server_updates'] = r'''"""Install a staged server update only while its game ports are free."""
import hashlib,json,os,shutil,time
from pathlib import Path

def install_pending(base):
    base=Path(base);folder=base/'server';pending=folder/'CSO2-LocalServer.pending.exe'
    manifest=folder/'pending_update.json'
    if not pending.exists():return False
    spec=json.loads(manifest.read_text(encoding='utf-8'))
    if hashlib.sha256(pending.read_bytes()).hexdigest()!=spec['sha256']:
        raise RuntimeError('待更新服务端校验失败，原程序保留。')
    native=folder/'CSO2-LocalServer.exe'
    if native.exists():
        backup=base/'backups'/time.strftime('%Y%m%d_%H%M%S_server_update');backup.mkdir(parents=True,exist_ok=True)
        shutil.copy2(native,backup/native.name)
    os.replace(pending,native)
    manifest.unlink()
    return True
'''

# --- ui_language ---
MODULE_SOURCES['ui_language'] = r'''"""Window-local Chinese/English presentation; never rewrites command or entry values."""
import ctypes
import re
import tkinter as tk
from tkinter import ttk

EN = {
 '0.25～3 倍':'0.25–3x','生化 ZETA · 变异技能':'Zombie ZETA · Mutations','仅生化 ZETA 模式可用。':'Available in Zombie ZETA only.',
 '单次 1～10':'1–10 per request','在线刷枪':'Give weapons','对所有人有效':'Applies to all players','对自己有效':'Applies to you',
 '游戏内喊话':'In-game chat','状态以游戏实值为准':'Status follows actual game values',
 '输入名称或中文功能关键词搜索。选择一项后可查看原生帮助。':'Search by command name or description. Select a command for native help.',
 '立即设置':'Set now','每局自动设置':'Set each round', '每局设置已更新：':'Round setting updated: ',
 '每局设置已停止：':'Round settings stopped: ',
 '每局设置':'Set each round','设置玩家数值':'Set player values','锁定玩家数值':'Lock player values',
 '暂时无法读取游戏内存状态。':'Game memory status is temporarily unavailable.',
 '游戏进程已变化，等待重新读取状态。':'Game process changed; waiting for a new sample.',
 '地址空间剩余 ':'Free address space ', ' · 最大连续空块 ':' · Largest free block ',
 '。空间严重不足，继续加载模型可能退出；建议退出游戏后重新启动。':'. Very little space remains; model loading may fail. Restart the game when ready.',
 '。空间偏紧，换图或换装可能耗尽；可在下次启动前开启低内存画质。':'. Space is low; changing maps or models may exhaust it. Low-memory graphics can help on next launch.',
 '（仅当前采样，不能保证下一次加载成功）。':' (current sample only; the next allocation may still fail).',
 '作弊设置已保存；等待本目录的服务器启动。':'Cheat setting saved; waiting for the server from this folder.',
 '作弊设置已保存；等待监控器确认（旧状态已过期）。':'Cheat setting saved; waiting for a fresh monitor confirmation.',
 '作弊设置已保存；等待游戏应用最新选择。':'Cheat setting saved; waiting for the game to apply the latest choice.',
 '作弊状态：':'Cheat status: ','等待游戏确认':'Waiting for game confirmation',
 '未发现同时加载 client.dll 和 engine.dll 的客户端':'No client with both client.dll and engine.dll loaded',
 'CSO2房主工具PYTHON重做':'CSO2 Host Tool', 'CSO2 房主工具':'CSO2 Host Tool',
 'CSO2 本地服务端':'CSO2 Local Server', 'CSO2 本地启动器':'CSO2 Local Launcher',
 'CSO2 / 本地服务端':'CSO2 / Local Server', 'CSO2 / 本地游戏':'CSO2 / Local Game',
 '本地账号自动登录 · 窗口大小与显示方式可自定义':'Automatic local login · Custom resolution and display mode',
 '保存设置':'Save settings','停止全部':'Stop all','连接游戏':'Connect','管理员连接':'Connect as admin',
 '钱血':'Players','功能':'Features','喊话':'Chat','指令':'Commands','展开日志':'Show log','收起日志':'Hide log',
 '未连接游戏':'Not connected','灰色按钮移上去可看原因。':'Hover over a disabled button to see why.',
 '全选':'Select all','取消勾选':'Clear checks','选择':'Select','编号':'ID','昵称':'Name','血量':'HP','金钱':'Money',
 '阵营':'Team','状态':'Status','观战':'Spectator','死亡':'Dead','存活':'Alive','自己':'You',
 '进入对局后显示玩家列表':'Players appear after joining a match','修改所选玩家':'Edit checked players',
 '设置血量':'Set HP','设置金钱':'Set money','锁定所选玩家血量':'Lock checked HP','锁定所选玩家金钱':'Lock checked money',
 '投票踢出':'Vote kick','无票踢出':'Kick directly','传送到此人身边':'Go to player','将此人传送过来':'Bring player',
 '复制名字':'Copy name','操作高亮玩家':'Act on highlighted player','请先点选一名玩家':'Select a player first',
 '请先连接游戏并进入对局':'Connect and join a match first','不能对自己执行此操作':'Cannot use this action on yourself',
 '观战或电视实体不能作为此操作目标':'This action cannot target a spectator or TV entity',
 '通用功能':'General','开启作弊功能（sv_cheats）':'Enable cheats (sv_cheats)','无限子弹':'Infinite ammo',
 '头部 / 身体大小':'Head / body size','头部':'Head','身体':'Body','应用比例':'Apply scale','随时购买枪械':'Buy anywhere',
 '武器':'Weapons','生成到自己':'Give to self','生化 ZETA':'Zombie ZETA','增加':'Add','读取次数':'Read count',
 '刷新机器':'Find machines','重抽机器技能':'Reroll machine','增加变异次数':'Add mutations',
 '进入生化 ZETA 后可读取次数和机器列表。':'Join Zombie ZETA to read mutation counts and machines.',
 '当前地图没有变异机器':'No mutation machines on this map','已启用':'Enabled','未启用':'Disabled',
 '全体':'All','团队':'Team','间隔':'Interval','秒':'seconds','立即发言':'Send now','定时发言':'Repeat chat',
 '只发到当前对局；退出对局自动停止。':'Sent only to this match; stops when you leave.',
 '默认':'Default','自定义':'Custom','更多命令':'Command catalog','人机操作':'Bots','人机数量':'Bot count',
 '设置数量':'Set count','难度':'Difficulty','设置难度':'Set difficulty','0 简单':'0 Easy','1 普通偏易':'1 Normal easy',
 '2 普通':'2 Normal','3 较难':'3 Challenging','4 困难':'4 Hard','5 很难':'5 Very hard','6 专家':'6 Expert','7 精英':'7 Elite',
 '加一人机':'Add bot','删除人机':'Remove bots','处死人机':'Kill bots','刷新游戏':'Restart round',
 '加入 T 人机':'Add T bot','加入 CT 人机':'Add CT bot','暂停人机':'Pause bots','恢复人机':'Resume bots',
 '常用指令':'Quick commands','进入观战':'Join spectators','开启队友伤害':'Enable friendly fire','关闭队友伤害':'Disable friendly fire',
 'BOT 语音关闭':'Mute bot chatter','人机只用刀':'Bots use knives','恢复所有武器':'Restore all weapons',
 '说明':'Description','＋ 新增':'+ Add','临时指令':'Quick command','发送':'Send','存为自定义':'Save as custom',
 '全部':'All','回合':'Rounds','经济':'Economy','玩家':'Players','生化':'Zombie','环境':'World','查询':'Queries','其他':'Other',
 '命令名':'Command','类型':'Type','命令':'Command','变量':'Variable','路由':'Route','加入自定义':'Add to custom',
 '执行选中指令':'Run selected command','选择一条指令查看说明':'Select a command to view its description',
 '无原生帮助文本':'No native help text','游戏没有提供帮助文本；请确认参数后再发送。':'No native help; check parameters before sending.',
 '作弊标志':'Cheat flag','开发者标志':'Developer flag','隐藏标志':'Hidden flag',
 '选择游戏目录':'Choose game folder','导出便携副本':'Export portable copy','打开操作日志':'Open operation log','断开游戏':'Disconnect',
 '游戏分辨率':'Game resolution','全屏':'Fullscreen','宽度':'Width','高度':'Height','保存显示设置':'Save display settings',
 '下次启动游戏生效；不勾选全屏即为有边框窗口。':'Applies next launch. Uncheck fullscreen for a bordered window.',
 '低内存画质（下次启动游戏生效）':'Low-memory graphics (next launch)',
 '降低纹理、关闭抗锯齿与部分特效，减少内存占用；取消后下次启动恢复。':'Reduce textures, antialiasing and effects to save memory. Uncheck to restore on next launch.',
 '正在读取游戏地址空间…':'Reading game memory status…','游戏未运行。':'Game is not running.',
 '正在检查服务状态…':'Checking server status…','本地 CSO2 路径':'Local CSO2 folder',
 '可选择游戏目录、Bin 目录，或包含游戏的上层文件夹。':'Choose the game folder, its Bin folder, or a parent folder.',
 '选择文件夹并扫描':'Choose folder and scan','取消扫描':'Cancel scan',
 '不把我随机选成僵尸 / 恶灵（仅 BOT 参与初始选择）':'Exclude me from random zombie / spirit selection (bots only)',
 '开地图不用等五秒':'Skip the five-second start delay',
 '进入本地对局后自动应用；取消勾选关闭。房主工具使用同一设置。':'Applied automatically in local matches. Uncheck to disable. Shared with the host tool.',
 '尚未指定作弊设置；勾选后开启，取消后关闭。':'No cheat preference set. Check to enable or uncheck to disable.',
 '等待本地服务器与游戏状态…':'Waiting for local server and game status…',
 '生化、恶灵附身：更改后下次加载地图生效；被攻击感染规则保留。':'Zombie / possession: changes apply next map. Infection from attacks still applies.',
 '本地账号：':'Local account: ', '    密码已保存':'    Password saved',
 '启动本地服务':'Start local server','启动游戏':'Launch game','保存当前存档':'Save progress','停止服务并保存':'Stop server and save',
 '查看日志':'View logs','单人开图 · 选择模式与地图':'Solo game · Choose mode and map',
 '关闭面板后服务继续运行。已有对局运行时不会自动重启服务。':'Closing this panel keeps the server running. Active matches are never restarted automatically.',
 '本地服务已就绪 · 游戏运行中':'Local server ready · Game running','本地服务已就绪':'Local server ready','本地服务未启动':'Local server stopped',
 '正在处理…':'Working…','正在扫描…':'Scanning…','扫描已取消，原路径保留。':'Scan cancelled; previous path retained.',
 '已找到并保存。服务运行中更换路径将在重启服务后使用。':'Found and saved. A running server uses the new path after its next restart.',
 '规则已保存；下次加载地图生效。':'Rule saved; applies next map.',
 '开局等待设置已保存。新版服务下次开图生效；旧服务需退出对局后重启。':'Start-delay setting saved. Applies next map on the updated server; older servers need a restart after the match.',
 '作弊设置已保存；本地对局就绪后自动应用并核对。':'Cheat setting saved; applies and verifies when a local match is ready.',
 '作弊设置已保存；下次从本目录启动服务后自动应用。':'Cheat setting saved; applies when the server is next started here.',
 '低内存画质已保存；下次启动游戏生效。当前对局画质保持原值。':'Low-memory graphics saved for next launch. Current match graphics stay unchanged.',
 '显示设置已保存，下次启动游戏生效。':'Display settings saved for next launch.','显示设置':'Display settings',
 '选择文件夹，自动扫描本地 CSO2':'Choose a folder to scan for local CSO2',
 '未取得游戏内存状态。':'Game memory status is unavailable.',
 '未指定作弊设置，保持游戏原值。':'No cheat preference set; keeping the game value.',
 '作弊设置已保存；等待对局应用。':'Cheat setting saved; waiting for a match.',
 '原目录服务仍运行；当前对局结束后停止服务，再从这里启动。':'The server from the old folder is running. Stop it after the match, then start it here.',
 'CSO2 单人开图':'CSO2 Solo Game','单人开图':'Solo game','进入所选地图':'Start selected map',
 '先登录游戏进入大厅；退出当前房间后可直接开图。':'Log in and enter the lobby. Leave your current room before starting.',
 '允许单人开始；默认 CT 3 名、TR 4 名人机。\n人机数量和难度也可在游戏房间设置中调整。':'Solo start allowed: 3 CT and 4 TR bots by default.\nYou can change bot count and difficulty in the game room.',
 '该模式没有可选地图。':'No maps available for this mode.',
 '尚未连接并验证':'Not connected or checked yet','等待验证当前指令':'Waiting to check this command','当前不可用':'Currently unavailable',
 '点击执行：':'Click to run: ','启动完成，正在自动连接游戏。':'Ready; connecting to the game automatically.',
 '离线界面检查：未执行游戏操作':'Offline UI check: no game operations executed',
 '已复制名字：':'Name copied: ','操作已入队，等待游戏处理：':'Action queued; waiting for the game: ',
 '已提交：':'Submitted: ','；等待游戏处理。':'; waiting for the game.',
 '当前功能不可用':'Feature unavailable','请先选择一条命令':'Select a command first',
 '没有选择有效玩家，操作未执行':'No valid player selected; action cancelled',
 '启动完成':'Ready','已停止持续功能与定时喊话':'Continuous features and repeat chat stopped',
 '请选择存活玩家':'Select a living player','需要先开启 sv_cheats':'Enable sv_cheats first',
}
PATTERNS = [
 (r'已勾选 (\d+) 人',lambda m:f'{m[1]} checked'),
 (r'已扫描 (\d+) 个文件夹，发现 (\d+) 份客户端…',lambda m:f'Scanned {m[1]} folders; found {m[2]} clients…'),
 (r'找到 (\d+) 份客户端，请在列表中选择。',lambda m:f'Found {m[1]} clients. Select one from the list.'),
 (r'未找到完整客户端；扫描 (\d+) 个文件夹，跳过 (\d+) 个不可读目录。',lambda m:f'No complete client found; scanned {m[1]} folders, skipped {m[2]} unreadable folders.'),
 (r'([\d,]+) 项结果 · 已确认登记不代表所有模式都允许执行',lambda m:f'{m[1]} results · Registered commands may be restricted by game mode'),
 (r'(.+) · (\d+) 名玩家',lambda m:f'{m[1]} · {m[2]} players'),
]

def detect_language():
    try:return 'zh' if ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3ff == 4 else 'en'
    except (AttributeError,OSError):return 'en'

class UiLanguage:
    def __init__(self,root,language=None):
        self.root=root;self.lang=language or detect_language();self.widgets={};self.variables={};self.buttons=[]
        self.tabs=[];self.headings=[];self.combos=[];self.reverse={v:k for k,v in EN.items()};self.rendered={};self.callbacks=[]
        root.ui_language=self;self.title_source=root.title()
    def source(self,text):return self.rendered.get(str(text),self.reverse.get(str(text),str(text)))
    def t(self,text):
        raw=self.source(text)
        if self.lang=='zh':return raw
        translated=EN.get(raw)
        if translated is None:
            for pattern,render in PATTERNS:
                match=re.fullmatch(pattern,raw)
                if match:translated=render(match);break
        if translated is None:
            translated=raw
            for original,english in sorted(EN.items(),key=lambda row:-len(row[0])):
                # UI captions only. Never apply this to user names or command input.
                if len(original)>=4:translated=translated.replace(original,english)
        if translated!=raw:
            if len(self.rendered)>1024:self.rendered.clear()
            self.rendered[translated]=raw
        return translated
    def button(self,parent,**kw):
        button=ttk.Button(parent,text='English' if self.lang=='zh' else '中文',command=self.toggle,**kw)
        self.buttons.append(button);return button
    def capture(self,widget):
        if widget in self.widgets:return
        if isinstance(widget,(tk.Label,tk.Button,tk.Checkbutton,tk.Radiobutton,tk.LabelFrame,
                              ttk.Label,ttk.Button,ttk.Checkbutton,ttk.Radiobutton,ttk.LabelFrame)) and widget not in self.buttons:
            raw=str(widget.cget('text'));self.widgets[widget]=raw;original=widget.configure
            def configure(cnf=None,_w=widget,_orig=original,**kw):
                if isinstance(cnf,dict):kw=dict(cnf,**kw);cnf=None
                if 'text' in kw:self.widgets[_w]=self.source(kw['text']);kw['text']=self.t(kw['text'])
                return _orig(cnf,**kw)
            widget.configure=widget.config=configure
            try:variable=str(widget.cget('textvariable'))
            except tk.TclError:variable=''
            if variable and variable not in self.variables:
                var=tk.StringVar(master=self.root,name=variable);state={'raw':self.source(var.get()),'updating':False}
                def changed(*_,_v=var,_s=state):
                    if _s['updating']:return
                    _s['raw']=self.source(_v.get());_s['updating']=True
                    try:_v.set(self.t(_s['raw']))
                    finally:_s['updating']=False
                token=var.trace_add('write',changed);self.variables[variable]=(var,state,token);changed()
            widget.configure(text=raw)
        if isinstance(widget,ttk.Notebook):
            known={(id(w),tab) for w,tab,_ in self.tabs}
            for tab in widget.tabs():
                if (id(widget),tab) not in known:self.tabs.append((widget,tab,self.source(widget.tab(tab,'text'))))
        if isinstance(widget,ttk.Treeview):
            known={(id(w),col) for w,col,_ in self.headings}
            for col in widget['columns']:
                if (id(widget),col) not in known:self.headings.append((widget,col,self.source(widget.heading(col,'text'))))
        if isinstance(widget,ttk.Combobox) and widget not in [row[0] for row in self.combos]:
            values=tuple(widget['values'])
            if values and any(str(v) in EN for v in values):self.combos.append((widget,values))
        for child in widget.winfo_children():self.capture(child)
    def refresh(self):
        self.root.title(self.t(self.title_source))
        for widget,raw in list(self.widgets.items()):
            if widget.winfo_exists():widget.configure(text=raw)
            else:self.widgets.pop(widget,None)
        for var,state,_ in self.variables.values():
            state['updating']=True
            try:var.set(self.t(state['raw']))
            finally:state['updating']=False
        for widget,tab,raw in self.tabs:
            if widget.winfo_exists():widget.tab(tab,text=self.t(raw))
        for widget,col,raw in self.headings:
            if widget.winfo_exists():widget.heading(col,text=self.t(raw))
        for widget,values in self.combos:
            if widget.winfo_exists():
                selected=widget.current();widget.configure(values=[self.t(v) for v in values])
                if selected>=0:widget.current(selected)
        for button in self.buttons:button.configure(text='English' if self.lang=='zh' else '中文')
        for callback in self.callbacks:callback()
    def toggle(self):
        self.lang='en' if self.lang=='zh' else 'zh';self.refresh()
'''

# --- restore_reshade ---
MODULE_SOURCES['restore_reshade'] = r'''"""Restore the backed-up inactive wrapper without modifying game quality settings."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib,json

def main():
    base=Path(__file__).resolve().parent
    record=json.loads((base/'restore/reshade.json').read_text(encoding='utf-8'))
    from game_paths import load_local_config, validate_game
    game=validate_game(load_local_config(base/'local_config.json').get('game_root'))
    if game is None:raise RuntimeError('请先在本地启动器选择有效的游戏目录')
    original=game/'Bin/d3d9.dll';disabled=game/'Bin/d3d9.dll.reshade-disabled'
    from client_diagnostics import kernel,modules
    # Enumerating same-name processes via Toolhelp avoids killing any client.
    class Entry(C.Structure):
        _fields_=[('size',W.DWORD),('usage',W.DWORD),('pid',W.DWORD),('heap',C.c_size_t),('module',W.DWORD),
                  ('threads',W.DWORD),('parent',W.DWORD),('priority',W.LONG),('flags',W.DWORD),('exe',W.WCHAR*260)]
    k=kernel();k.Process32FirstW.argtypes=[W.HANDLE,C.POINTER(Entry)];k.Process32NextW.argtypes=[W.HANDLE,C.POINTER(Entry)]
    h=k.CreateToolhelp32Snapshot(2,0)
    if h==C.c_void_p(-1).value:raise RuntimeError('无法检查游戏是否运行，未改动文件')
    try:
        row=Entry();row.size=C.sizeof(row);ok=k.Process32FirstW(h,C.byref(row))
        while ok:
            if row.exe.lower()=='counterstrikeonline2.exe':raise RuntimeError('请先退出 CSO2 再恢复')
            ok=k.Process32NextW(h,C.byref(row))
    finally:k.CloseHandle(h)
    if original.exists():raise RuntimeError('原位置已有 d3d9.dll，未覆盖')
    if hashlib.sha256(disabled.read_bytes()).hexdigest()!=record['sha256']:raise RuntimeError('备份校验失败，未改动文件')
    disabled.rename(original)
    return '已恢复原 ReShade。画质配置未改动。'

if __name__=='__main__':main()
'''

# --- bundle_tools ---
MODULE_SOURCES['bundle_tools'] = r'''"""Entry points shared by the launcher menu and command line."""
from pathlib import Path
import subprocess
import sys


def open_server_panel():
    python = Path(sys.executable)
    windowless = python.with_name('pythonw.exe')
    if windowless.is_file():
        python = windowless
    subprocess.Popen([str(python), str(BUNDLE_ENTRY), '--server-panel'],
                     cwd=DEPENDENCY_ROOT, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))


def restore_client_patch():
    from game_paths import load_local_config, validate_game
    from client_cache_patch import apply_pending
    game = validate_game(load_local_config().get('game_root'))
    if game is None:
        raise RuntimeError('请先在本地启动器选择有效的游戏目录')
    result = apply_pending(game, restore=True)
    if result['status'] == 'restored':
        return '已恢复原版，并关闭自动应用。'
    if result['status'] == 'pending':
        return '已关闭自动应用。游戏仍在运行或文件被占用；退出后，下次从本地启动器启动前会恢复原版。'
    return result.get('reason', '未修改客户端。')


def restore_reshade():
    from restore_reshade import main
    return main()
'''

# --- local_update ---
MODULE_SOURCES['local_update'] = r'''"""Discover public releases and replace only this application's PYW."""
import ast
import base64
import ctypes
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from urllib.parse import quote, urlsplit

META = UPDATE_METADATA
LIMIT = 8 * 1024 * 1024
TITLE = 'CSO2 Local Master Server Update'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', value):
        raise ValueError('Invalid release version')
    return tuple(map(int, value.split('.')))


def trusted(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or parsed.hostname not in
            {'api.github.com', 'github.com', 'raw.githubusercontent.com',
             'objects.githubusercontent.com', 'release-assets.githubusercontent.com'}
            or parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ValueError('Invalid GitHub update address')
    return value


def fetch(url, limit=LIMIT, raw=False):
    class Redirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            trusted(newurl)
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    headers = {'User-Agent': 'CSO2-Local-Master-Server/' + META['version'],
               'Accept': 'application/vnd.github.raw+json' if raw else 'application/vnd.github+json',
               'X-GitHub-Api-Version': '2022-11-28'}
    req = urllib.request.Request(trusted(url), headers=headers)
    with urllib.request.build_opener(Redirect).open(req, timeout=25) as response:
        trusted(response.url)
        if int(response.headers.get('Content-Length', '0')) > limit:
            raise ValueError('Update response exceeds size limit')
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Update response exceeds size limit')
        return data


def fetch_json(url):
    return json.loads(fetch(url))


def filename(value):
    if (not isinstance(value, str) or not value or len(value) > 200
            or re.search(r'[\x00-\x1f/\\:<>"|?*]', value)
            or value.endswith((' ', '.')) or not value.lower().endswith('.pyw')
            or re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])\..*', value)):
        raise ValueError('Invalid script filename')
    return value


def regular(path):
    path = Path(path)
    for parent in (path, *path.parents):
        if parent.exists():
            info = parent.lstat()
            if parent.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ValueError('Update paths cannot use symbolic links or junctions')


def discover(target, get_json=None, page_only=False):
    get_json = get_json or fetch_json
    repo = get_json(f"https://api.github.com/repositories/{META['repository_id']}")
    if repo.get('id') != META['repository_id']:
        raise ValueError('Update repository identity mismatch')
    api = trusted(repo['url'])
    candidates = []
    for page in range(1, 11):
        rows = get_json(api + f'/releases?per_page=100&page={page}')
        if not isinstance(rows, list):
            raise ValueError('Invalid releases response')
        for release in rows:
            tag = str(release.get('tag_name', ''))
            if release.get('draft') or release.get('prerelease') or not tag.startswith(META['tag_prefix']):
                continue
            try:
                number = version(tag[len(META['tag_prefix']):])
            except ValueError:
                continue
            if page_only or number >= version(META['version']):
                candidates.append((number, release))
        if len(rows) < 100:
            break
    if not candidates:
        return trusted(repo['html_url'].rstrip('/') + '/releases') if page_only else None
    tree = get_json(api + '/git/trees/' + quote(repo['default_branch'], safe='') + '?recursive=1')
    if tree.get('truncated') or not isinstance(tree.get('tree'), list):
        raise ValueError('Incomplete repository source tree')
    blobs = {r['path']: r for r in tree['tree'] if r.get('type') == 'blob'}
    for _, release in sorted(candidates, key=lambda row: row[0], reverse=True):
        suffix = '/releases/' + release['tag_name'] + '/' + META['product'] + '.release.json'
        matches = [r for path, r in blobs.items() if path.endswith(suffix)]
        if not matches:
            continue
        if len(matches) != 1 or not 0 < matches[0].get('size', 0) <= 65536:
            raise ValueError('Ambiguous release metadata')
        row = matches[0]
        blob = get_json(trusted(row['url']))
        if blob.get('encoding') != 'base64':
            raise ValueError('Invalid release metadata encoding')
        manifest = json.loads(base64.b64decode(blob['content']))
        if (manifest.get('schema') != 3 or manifest.get('product') != META['product']
                or manifest.get('repository_id') != META['repository_id']
                or release['tag_name'] != META['tag_prefix'] + manifest.get('version', '')):
            raise ValueError('Incompatible release metadata')
        version(manifest['version'])
        page_url = trusted(release['html_url'])
        if page_only:
            return page_url
        entry = filename(manifest.get('entry'))
        script_path = row['path'].rsplit('/', 1)[0] + '/' + entry
        script = blobs.get(script_path)
        size = manifest.get('size'); checksum = manifest.get('sha256', '')
        if (type(size) is not int or not 0 < size <= LIMIT
                or not re.fullmatch('[a-f0-9]{64}', checksum)
                or not script or script.get('size') != size):
            raise ValueError('Release script is missing or invalid')
        before = digest(target)
        if before == checksum:
            return None
        return dict(version=manifest['version'], size=size, sha256=checksum,
                    before_sha256=before, download_url=trusted(script['url']), page_url=page_url)
    return trusted(repo['html_url'].rstrip('/') + '/releases') if page_only else None


def validate_source(data, release_version):
    if not 0 < len(data) <= LIMIT:
        raise ValueError('Invalid script size')
    tree = ast.parse(data.decode('utf-8-sig'))
    wanted = dict(APP_ID=META['product'], APP_VERSION=release_version,
                  UPDATE_REPOSITORY_ID=META['repository_id'], UPDATE_PROTOCOL=3,
                  UPDATE_TAG_PREFIX=META['tag_prefix'])
    found = {}; embedded = 0
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for name in node.targets:
                if isinstance(name, ast.Name) and name.id in wanted:
                    if name.id in found:
                        raise ValueError('Duplicate update identity')
                    found[name.id] = ast.literal_eval(node.value)
                if (isinstance(name, ast.Subscript) and isinstance(name.value, ast.Name)
                        and name.value.id == 'MODULE_SOURCES'):
                    compile(ast.literal_eval(node.value), '<embedded update module>', 'exec')
                    embedded += 1
    if found != wanted or embedded < 20:
        raise ValueError('Downloaded script is not a compatible Local Master Server release')
    compile(tree, '<Local Master Server update>', 'exec')


def write_json(path, value):
    temp = path.with_suffix('.tmp')
    with temp.open('w', encoding='utf-8') as stream:
        json.dump(value, stream)
        stream.flush(); os.fsync(stream.fileno())
    os.replace(temp, path)


def prepare(target, info, download=None):
    target = Path(target).absolute(); regular(target)
    if target.with_name(target.name + '.OLD').exists():
        raise RuntimeError('已有 OLD 备份，请先保留或恢复它，再重新更新。')
    before = digest(target)
    if before != info['before_sha256']:
        raise RuntimeError('本地脚本已改变，请重新检查更新。')
    payload = (download or fetch)(info['download_url'], info['size'], raw=True)
    if len(payload) != info['size'] or hashlib.sha256(payload).hexdigest() != info['sha256']:
        raise ValueError('下载校验失败，未替换本地文件。')
    validate_source(payload, info['version'])
    token = secrets.token_hex(16)
    stage = target.parent / ('.cso2-local-update-' + token)
    stage.mkdir()
    try:
        with (stage / 'incoming.pyw').open('xb') as output:
            output.write(payload); output.flush(); os.fsync(output.fileno())
        shutil.copyfile(target, stage / 'runner.pyw')
        ticket = stage / 'ticket.json'
        write_json(ticket, dict(schema=3, product=META['product'], repository_id=META['repository_id'],
                   token=token, target=target.name, parent_pid=os.getpid(), version=info['version'],
                   before_sha256=before, after_sha256=info['sha256']))
        return ticket
    except Exception:
        shutil.rmtree(stage)
        raise


def read_ticket(ticket):
    ticket = Path(ticket).absolute(); regular(ticket)
    if ticket.name != 'ticket.json' or ticket.stat().st_size > 16384:
        raise ValueError('Invalid update ticket')
    plan = json.loads(ticket.read_text(encoding='utf-8'))
    token = plan.get('token', '')
    if (not re.fullmatch('[a-f0-9]{32}', str(token))
            or ticket.parent.name != '.cso2-local-update-' + token
            or plan.get('schema') != 3 or plan.get('product') != META['product']
            or plan.get('repository_id') != META['repository_id']
            or type(plan.get('parent_pid')) is not int or plan['parent_pid'] <= 0):
        raise ValueError('Invalid update identity')
    version(plan['version'])
    for key in ('before_sha256', 'after_sha256'):
        if not re.fullmatch('[a-f0-9]{64}', str(plan.get(key, ''))):
            raise ValueError('Invalid update checksum')
    target = ticket.parent.parent / filename(plan.get('target'))
    regular(target)
    return plan, target


def spawn(arguments):
    python = Path(sys.executable)
    if python.with_name('pythonw.exe').is_file():
        python = python.with_name('pythonw.exe')
    return subprocess.Popen([str(python), '-X', 'utf8', *map(str, arguments)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), close_fds=True)


def wait_parent(pid):
    if pid == os.getpid():
        raise ValueError('Updater must run in a separate process')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]; kernel.OpenProcess.restype = W.HANDLE
    kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]; kernel.WaitForSingleObject.restype = W.DWORD
    kernel.CloseHandle.argtypes = [W.HANDLE]; kernel.CloseHandle.restype = W.BOOL
    handle = kernel.OpenProcess(0x100000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return
        raise OSError('Cannot verify previous application exit')
    try:
        if kernel.WaitForSingleObject(handle, 60000) != 0:
            raise TimeoutError('原窗口尚未关闭，更新已取消。')
    finally:
        kernel.CloseHandle(handle)


def acknowledge(ticket, target):
    plan, expected = read_ticket(ticket)
    if (expected.resolve() != Path(target).resolve() or plan['version'] != META['version']
            or digest(target) != plan['after_sha256']):
        raise ValueError('New window identity or file checksum mismatch')
    write_json(Path(ticket).parent / 'ready.json', dict(token=plan['token'], pid=os.getpid()))


def apply(ticket, wait=None, launch=None, timeout=75, notify=None):
    ticket = Path(ticket).absolute(); plan, target = read_ticket(ticket)
    stage = ticket.parent; incoming = stage / 'incoming.pyw'
    old = target.with_name(target.name + '.OLD')
    launch = launch or spawn
    notify = notify or (lambda message: ctypes.windll.user32.MessageBoxW(None, message, TITLE, 0x10))
    moved = installed = confirmed = False; child = None
    try:
        (wait or wait_parent)(plan['parent_pid'])
        regular(old); regular(incoming)
        if old.exists() or digest(target) != plan['before_sha256']:
            raise RuntimeError('本地文件已改变或已有 OLD 备份，未覆盖。')
        if digest(incoming) != plan['after_sha256']:
            raise ValueError('Downloaded script changed after verification')
        validate_source(incoming.read_bytes(), plan['version'])
        os.rename(target, old); moved = True
        os.replace(incoming, target); installed = True
        child = launch([target, '--local-update-ticket', ticket])
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError('新版在确认启动成功前退出。')
            ready = stage / 'ready.json'
            if ready.exists():
                message = json.loads(ready.read_text(encoding='utf-8'))
                if message != dict(token=plan['token'], pid=child.pid):
                    raise ValueError('Invalid startup acknowledgement')
                if digest(target) != plan['after_sha256']:
                    raise ValueError('Installed script changed before confirmation')
                confirmed = True
                if digest(old) != plan['before_sha256']:
                    raise RuntimeError('OLD 文件已改变，已保留。')
                old.unlink()
                shutil.rmtree(stage)
                return True
            time.sleep(.1)
        raise TimeoutError('未收到新版窗口启动成功确认。')
    except Exception as error:
        if confirmed:
            notify('新版已启动，旧文件清理未完成。\n' + str(error)); return True
        if child is not None and child.poll() is None:
            (stage / 'cancel').write_text(plan['token'], encoding='ascii')
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                notify('新版窗口尚未退出，OLD 已保留。\n' + str(error)); return False
        recovered = False
        if moved:
            try:
                if digest(old) != plan['before_sha256']:
                    raise RuntimeError('OLD changed; recovery stopped')
                if installed:
                    if digest(target) != plan['after_sha256']:
                        raise RuntimeError('New script changed; recovery stopped')
                    os.replace(target, incoming)
                elif target.exists():
                    raise RuntimeError('Target appeared; recovery stopped')
                os.replace(old, target); recovered = True
                launch([target, '--skip-local-update-once'])
            except Exception:
                pass
        notify(('更新失败，已恢复旧版。\n' if recovered else '更新未完成，原文件或 OLD 已保留。\n') + str(error))
        return False


class ReleaseUpdater:
    def __init__(self, root, close, state, language, ticket=None, skip=False):
        self.root = root; self.close = close; self.state = state; self.language = language
        self.ticket = Path(ticket) if ticket else None
        self.target = BUNDLE_ENTRY; self.inbox = queue.Queue(); self.busy = False
        self.dialog = None; self.info = None; self.notified = set()
        if self.ticket:
            read_ticket(self.ticket)
            self.root.after(800, self.confirm_startup)
        self.root.after(200, self.poll)
        if not skip:
            self.root.after(5000, self.periodic)

    def text(self, zh, en):
        return en if getattr(self.language, 'lang', 'zh') == 'en' else zh

    def run(self, action, kind, manual=False):
        if self.busy or self.state['closed']:
            return
        self.busy = True
        def worker():
            try: self.inbox.put((kind, action(), manual))
            except Exception as error: self.inbox.put(('error', str(error), manual))
        threading.Thread(target=worker, name='local-release-update', daemon=True).start()

    def check(self, manual=False):
        self.run(lambda: discover(self.target), 'checked', manual)

    def periodic(self):
        if self.state['closed']:
            return
        self.check()
        self.root.after(30 * 60 * 1000, self.periodic)

    def open_release(self):
        self.run(lambda: discover(self.target, page_only=True), 'page', True)

    def confirm_startup(self):
        if not self.state['closed'] and self.root.winfo_viewable():
            try:
                acknowledge(self.ticket, self.target)
            except Exception as error:
                self.inbox.put(('error', str(error), True))
        elif not self.state['closed']:
            self.root.after(200, self.confirm_startup)

    def show(self, info):
        import tkinter as tk
        from tkinter import ttk
        if self.dialog is not None and self.dialog.winfo_exists():
            self.dialog.lift(); return
        self.info = info
        dialog = self.dialog = tk.Toplevel(self.root)
        dialog.title(TITLE); dialog.transient(self.root); dialog.resizable(False, False)
        frame = ttk.Frame(dialog, padding=20); frame.pack(fill='both', expand=True)
        ttk.Label(frame, text=self.text('发现更新', 'Update available'), font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='v' + META['version'] + ' → v' + info['version']).pack(anchor='w', pady=8)
        ttk.Label(frame, text=self.text('更新后自动重启，启动成功后删除 OLD 旧文件。',
                  'Restart after updating; remove OLD after successful startup.')).pack(anchor='w')
        buttons = ttk.Frame(frame); buttons.pack(anchor='w', pady=(14, 0))
        self.download_button = ttk.Button(buttons, text=self.text('自动下载并更新', 'Download and update'), command=self.download)
        self.download_button.pack(side='left')
        def manual():
            import webbrowser
            webbrowser.open(trusted(info['page_url']))
        ttk.Button(buttons, text=self.text('手动更新：打开 Release', 'Open Release'), command=manual).pack(side='left', padx=10)
        self.progress = ttk.Label(frame, text='', wraplength=480); self.progress.pack(anchor='w', pady=(10, 0))

    def download(self):
        if self.busy or self.state['busy'] or self.state['scanning']:
            return
        self.download_button.state(['disabled'])
        self.progress.configure(text=self.text('正在下载并校验…', 'Downloading and verifying…'))
        self.run(lambda: prepare(self.target, self.info), 'prepared', True)

    def poll(self):
        from tkinter import messagebox
        if self.state['closed']:
            return
        if self.ticket and (self.ticket.parent / 'cancel').exists():
            self.close(); return
        try:
            while True:
                kind, result, manual = self.inbox.get_nowait(); self.busy = False
                try:
                    if kind == 'checked':
                        if result and (manual or result['sha256'] not in self.notified):
                            self.notified.add(result['sha256']); self.show(result)
                        elif not result and manual:
                            messagebox.showinfo(TITLE, self.text('当前已是最新版本。', 'Already up to date.'), parent=self.root)
                    elif kind == 'page':
                        import webbrowser
                        webbrowser.open(trusted(result))
                    elif kind == 'prepared':
                        if self.state['busy'] or self.state['scanning']:
                            shutil.rmtree(result.parent)
                            raise RuntimeError('请等待当前操作结束，再点击更新。')
                        spawn([result.parent / 'runner.pyw', '--apply-local-update', result])
                        self.close()
                    elif kind == 'error' and manual:
                        raise RuntimeError(result)
                except Exception as error:
                    if self.dialog is not None and self.dialog.winfo_exists():
                        self.download_button.state(['!disabled'])
                        self.progress.configure(text=self.text('更新失败，可重试或打开 Release。', 'Retry or open Release.'))
                    messagebox.showerror(TITLE, str(error), parent=self.root)
        except queue.Empty:
            pass
        if not self.state['closed']:
            self.root.after(200, self.poll)
'''


class _BundledModules(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in MODULE_SOURCES:
            return importlib.util.spec_from_loader(fullname, self,
                origin=str(DEPENDENCY_ROOT / (fullname + '.py')))
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__file__ = str(DEPENDENCY_ROOT / (module.__name__ + '.py'))
        module.BUNDLE_ENTRY = BUNDLE_ENTRY
        module.DEPENDENCY_ROOT = DEPENDENCY_ROOT
        module.UPDATE_METADATA = dict(product=APP_ID, version=APP_VERSION,
                                      repository_id=UPDATE_REPOSITORY_ID, tag_prefix=UPDATE_TAG_PREFIX)
        module.UPDATE_STARTUP_TICKET = UPDATE_STARTUP_TICKET
        module.UPDATE_SKIP_ONCE = UPDATE_SKIP_ONCE
        exec(compile(MODULE_SOURCES[module.__name__], module.__file__, 'exec'),
             module.__dict__)

    def get_source(self, fullname):
        return MODULE_SOURCES[fullname]


sys.meta_path.insert(0, _BundledModules())


def initialize_local_config():
    """Generate installation-specific credentials without shipping old user data."""
    import json
    import os
    import secrets
    import socket
    import tempfile
    if not DEPENDENCY_ROOT.is_dir():
        raise RuntimeError('请把 Dependencies 外部依赖 文件夹与本程序放在同一目录。')
    config_path = DEPENDENCY_ROOT / 'local_config.json'
    if config_path.exists():
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    config = {
        'schema': 1,
        'instance': secrets.token_hex(16),
        'game_root': '',
        'account': {'username': 'local', 'password': secrets.token_hex(8)},
        'control_port': port,
        'control_token': secrets.token_hex(32),
        'width': 1280, 'height': 720, 'windowed': True,
        'borderless': False, 'low_memory': False,
        'rules': {'protect_human_selection': True, 'sv_cheats': False},
    }
    temp = None
    try:
        with tempfile.NamedTemporaryFile('w', encoding='utf-8',
                dir=DEPENDENCY_ROOT, prefix='.initial-config-',
                suffix='.tmp', delete=False) as output:
            temp = Path(output.name)
            json.dump(config, output, ensure_ascii=False, indent=2)
            output.flush()
            os.fsync(output.fileno())
        try:
            # Windows rename refuses to overwrite another launcher's new config.
            os.rename(temp, config_path)
        except FileExistsError:
            pass
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def main():
    global UPDATE_STARTUP_TICKET, UPDATE_SKIP_ONCE
    args = sys.argv[1:]
    if args and args[0] == '--apply-local-update':
        if len(args) != 2:
            raise ValueError('--apply-local-update requires a ticket')
        from local_update import apply
        return apply(args[1])
    if '--local-update-ticket' in args:
        index = args.index('--local-update-ticket')
        if index + 1 >= len(args):
            raise ValueError('Missing update startup ticket')
        UPDATE_STARTUP_TICKET = args[index + 1]
        del args[index:index + 2]
    if '--skip-local-update-once' in args:
        UPDATE_SKIP_ONCE = True
        args.remove('--skip-local-update-once')
    sys.argv[1:] = args
    initialize_local_config()
    if args and args[0] == '--cheats-worker':
        if len(args) != 2:
            raise ValueError('--cheats-worker requires a supervisor PID')
        from cheat_settings import watch
        return watch(int(args[1]))
    if args and args[0] == '--diagnostics-worker':
        if len(args) != 3:
            raise ValueError('--diagnostics-worker requires PID and game directory')
        from client_diagnostics import record
        return record(int(args[1]), args[2])
    if args and args[0] in ('--restore-client-patch', '--restore-reshade'):
        if len(args) != 1:
            raise ValueError('Restoration does not accept extra arguments')
        from bundle_tools import restore_client_patch, restore_reshade
        from tkinter import Tk, messagebox
        root = Tk()
        root.withdraw()
        try:
            action = restore_client_patch if args[0] == '--restore-client-patch' else restore_reshade
            messagebox.showinfo('恢复 / Restore', action(), parent=root)
        finally:
            root.destroy()
        return
    from launcher import main as launch
    return launch()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        import ctypes
        import traceback
        try:
            logs = DEPENDENCY_ROOT / 'logs'
            logs.mkdir(parents=True, exist_ok=True)
            with (logs / 'launcher_errors.log').open('a', encoding='utf-8') as output:
                traceback.print_exc(file=output)
        except OSError:
            pass
        worker = any(flag in sys.argv for flag in
                     ('--serve', '--cheats-worker', '--diagnostics-worker', '--apply-local-update'))
        if not worker:
            ctypes.windll.user32.MessageBoxW(None, str(error), 'CSO2 本地启动失败', 0x10)
        raise SystemExit(1)
