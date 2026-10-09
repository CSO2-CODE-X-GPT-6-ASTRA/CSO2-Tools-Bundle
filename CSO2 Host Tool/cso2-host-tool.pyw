# -*- coding: utf-8 -*-
# CSO2 Host Tool · Python 3.10+ · tkinter · 单文件便携版
# 程序源码直接可读，没有加壳或编码隐藏。只压缩内置命令数据库。
# 设置自动原子更新下方配置行，复制本文件即可携带配置。
from __future__ import annotations
_PORTABLE_SETTINGS_B64 = "e30="


# runtime_compat.py
"""Bounded, read-only discovery and address resolution for compatible CSO2 images.

Each enabled operation validates its instruction and field dependencies.
"""
from pathlib import Path
import hashlib,ipaddress,json,re,struct
from functools import lru_cache



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


class CompatibilityError(RuntimeError):pass


def path_key(path):return str(Path(path).resolve()).casefold()


def game_root(module_path):
    directory=Path(module_path).resolve().parent
    for candidate in (directory,*list(directory.parents)[:3]):
        if (candidate/'Data').is_dir():return candidate
    return directory.parent if directory.name.casefold() in ('bin','bin32','win32') else directory


def choose_candidate(candidates,preferred,probe=None):
    """A selected directory disambiguates; a stale directory does not block discovery."""
    if probe is not None:
        ranked=[(item,probe(item)) for item in candidates]
        ranked=[(item,rank) for item,rank in ranked if rank is not None]
        if not ranked:raise CompatibilityError('发现的客户端均暂不可读取，将自动重试')
        best=max(rank for _,rank in ranked)
        candidates=[item for item,rank in ranked if rank==best]
    wanted=path_key(preferred)
    matching=[item for item in candidates if wanted in
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
    report=dict(path=str(path),architecture='x86',image_size=image.image_size)
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


SERVER_SIGNATURES={
    0x989c0:bytes.fromhex('8d9004000083f9ff74440fb7c1c1e0040544faa510c1e9103948047531833800742c8b8d9004000083f9ff74210fb7c1c1e0040544faa510c1e910394804750e'),
    0x8d990:bytes.fromhex('8b81e006000023442404f7d81bc0f7d8c20400'),
}


def module_image(path):
    path=Path(path).resolve();stat=path.stat()
    return _cached_image(str(path),stat.st_size,stat.st_mtime_ns,stat.st_ctime_ns)


@lru_cache(maxsize=12)
def _cached_image(path,size,mtime,ctime):return PEImage.from_path(path)


def verify_family(module,name):
    base,size,path=module;image=module_image(path)
    if size!=image.image_size or not 0x10000<=base<base+size<=0xffff0000:
        raise CompatibilityError(name+' 加载范围不符')
    if name!='server.dll':raise CompatibilityError(name+' 未登记特征')
    for rva,signature in SERVER_SIGNATURES.items():
        hits=[]
        for section in image.sections:
            if not section['flags']&0x20000000:continue
            data=image.raw[section['offset']:section['offset']+section['stored']]
            pos=data.find(signature)
            while pos>=0:
                hits.append(section['rva']+pos)
                pos=data.find(signature,pos+1)
        if hits!=[rva]:raise CompatibilityError(name+f' 关键指令特征未适配：{rva:#x}')
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


# host_specs.py
COMPAT_SPECS = {'client.dll': {'anchors': {'local_player': [{'pattern': '140000000066c7461c0000c744241001000000a148b8cd11c706fce1bf1085c0740d50c7461400000000e836c07c008b4c24088bc65e64890d0000000083c410', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffff00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}, {'pattern': '140000000066c7461c0000c744241001000000a148b8cd11c706e038c21085c0740d50c7461400000000e846607c008b4c24088bc65e64890d0000000083c410', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffff00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}], 'entity_entries': [{'pattern': '740fb7f0c1e604c1e81039863045ee10756383be2c45ee1000745a39863045ee1075088bb62c45ee10eb0233f680be1f0200000075108b068bce8b80d8010000', 'mask': 'ffffffffffffffffffffffff00000000ffffffff00000000ffffffffff00000000ffffffff00000000ffffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}, {'pattern': '6383be2c45ee1000745a39863045ee1075088bb62c45ee10eb0233f680be1f0200000075108b068bce8b80d8010000ffd084c074260fb786780200008d8e3c02', 'mask': 'ffffff00000000ffffffffff00000000ffffffff00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}], 'highest_entity': [{'pattern': 'b445061100000000c644240c04b92845ee10c7056045fe10ffffffffc7055845fe1000000000e8780000008b4c2404b82845ee1064890d0000000083c410c3cc', 'mask': '00000000ffffffffffffffffffff00000000ffff00000000ffffffffffff00000000ffffffffffffffffffffffffffff00000000ffffffffffffffffffffffff', 'operand': 20}], 'attack': [{'pattern': '442404bae670be108338017e068b900c040000b9bc510b11e8b20a0000c705ecc0cd1100000000c3cccccccccccccc8b442404bae670be108338017e068b900c', 'mask': 'ffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffff00000000ffffffffffffffffffffffffffffffffff00000000ffffffffffffffff', 'operand': 20}, {'pattern': '442404bae670be108338017e068b900c040000b9bc510b11e9120a0000cccc8b442404bae670be108338017e068b900c040000b958520b11e9620a0000cccc8b', 'mask': 'ffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffff', 'operand': 20}], 'attack2': [{'pattern': '442404bae670be108338017e068b900c040000b9c8510b11e992070000cccc8b442404bae670be108338017e068b900c040000b9c8510b11e902070000cccc8b', 'mask': 'ffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffff', 'operand': 20}, {'pattern': '442404bae670be108338017e068b900c040000b9c8510b11e902070000cccc8b442404bae670be108338017e068b900c040000b980d3ec10e952070000cccc8b', 'mask': 'ffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffffffffffff00000000ffffffffffffffff', 'operand': 20}], 'netprop:m_iHealth': [{'pattern': '0000e87d8d060085dbc70500c0ce110081c410b93cc0ce11c7052cc0ce111c1200000f44f7c70504c0ce1100000000c70508c0ce1100000000893520c0ce11e8', 'mask': 'ffffffffffffffffffffff0000000000000000ff00000000ffff00000000ffffffffffffffffff00000000ffffffffffff00000000ffffffffffff00000000ff', 'operand': 20}, {'pattern': '0000893520c0ce11e8408d0600b978c0ce11c7053cc0ce110059c210c70568c0ce1198000000c70540c0ce1100000000c70544c0ce1100000000c7055cc0ce11', 'mask': 'ffffffff00000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}], 'netprop:m_iTeamNum': [{'pattern': '00c7050ca7ce1100000000c60500a7ce1100c705f0a6ce11845cc410c7051ca7ce11a0000000c705f4a6ce1100000000c705f8a6ce1100000000c70540a7ce11', 'mask': 'ffffff00000000ffffffffffff00000000ffffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}, {'pattern': '00000000c70598a6ce1150848a10e85d590700b9f0a6ce11c705b4a6ce116c5cc410c705e0a6ce11ec020000be602d8310c705b8a6ce1101000000c705bca6ce', 'mask': 'ffffffffffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffff00000000ffff00000000ffffffffffff000000', 'operand': 20}], 'netprop:m_hActiveWeapon': [{'pattern': '90858a10c705eca0ce114c0b0711e8fcaa0700b93ca1ce11c70500a1ce11ac50c410c7052ca1ce1100000000bed0819110c70504a1ce1106000000c70508a1ce', 'mask': '00000000ffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffff00000000ffff00000000ffffffffffff000000', 'operand': 20}, {'pattern': '28a1ce11981aee10e8b1aa0700bbd0819110c7053ca1ce11bc50c41085dbc70568a1ce110c0f0000bf70818a10c70540a1ce11000000000f44f7c70544a1ce11', 'mask': '0000000000000000ffffffffffff00000000ffff0000000000000000ffffffff00000000ffffffffff00000000ffff00000000ffffffffffffffffff00000000', 'operand': 20}], 'netprop:m_Local': [{'pattern': '11b988b7ce11c744245000000000e8ae870600b9c4b7ce11c70588b7ce114071be10c705b4b7ce1100000000c7058cb7ce1100000000c70590b7ce1100000000', 'mask': '00ff00000000ffffffffffffffffffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffff', 'operand': 20}, {'pattern': 'a8b7ce1170818a10e872870600b900b8ce11c705c4b7ce11a07ec410c705f0b7ce116c0f0000c705c8b7ce1106000000c705ccb7ce1100000000c705e8b7ce11', 'mask': '0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}], 'netprop:m_vecPunchAngle': [{'pattern': '00000000c70520b0ce1150848a10e87c7d0600b978b0ce11c7053cb0ce11287cc410c70568b0ce1158000000c70540b0ce1101000000c70544b0ce1100000000', 'mask': 'ffffffffffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffff', 'operand': 20}, {'pattern': '5cb0ce1150848a10e8407d0600b9b4b0ce11c70578b0ce113c7cc410c705a4b0ce116c000000c7057cb0ce1102000000c70580b0ce1100000000c70598b0ce11', 'mask': '0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}], 'netprop:m_vecOrigin': [{'pattern': '000000b95ca4ce11893540a4ce11e8d05b0700b998a4ce11c7055ca4ce11b45cc410c70588a4ce1178000000c70560a4ce1100000000c70564a4ce1100000000', 'mask': 'ffffffff00000000ffff00000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffff', 'operand': 20}, {'pattern': '7ca4ce1190808a10e8945b0700b9d4a4ce11c70598a4ce111050c210c705c4a4ce11d0030000c7059ca4ce1102000000c705a0a4ce1100000000c705b8a4ce11', 'mask': '0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}], 'netprop:m_iClip1': [{'pattern': '00c705b450ce1100000000c605a850ce1100c7059850ce11d02bc210c705c450ce11300a0000c7059c50ce1100000000c705a050ce1100000000c705e850ce11', 'mask': 'ffffff00000000ffffffffffff00000000ffffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}, {'pattern': '90858a10c7054850ce116004ee10e8861e1500b99850ce11c7055c50ce11602dc210c7058850ce1100000000be40819110c7056050ce1106000000c7056450ce', 'mask': '00000000ffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffff00000000ffff00000000ffffffffffff000000', 'operand': 20}], 'netprop:m_hMyWeapons': [{'pattern': '4120f30f7e842488000000660fd64130894138b978a1ce11e85bab070083c44c8b4c2448b8010000005f5ec705ac1aee10c4a0ce11c705b01aee1004000000c7', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffffffffffffffffffffffffffffffffffffffffff0000000000000000ffff00000000ffffffffff', 'operand': 20}], 'netprop:m_iAmmo': [{'pattern': '4120f30f7e842488000000660fd64130894138b92cb9ce11e8f786060083c44cb968b9ce11e87a850600b9a4b9ce11c70568b9ce11707ec410c70594b9ce1170', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffffffffffffffffff00000000ffffffffffff00000000ffff0000000000000000ffff00000000ff', 'operand': 20}], 'netprop:m_iPrimaryAmmoType': [{'pattern': '00c705904ece1100000000c605844ece1100c705744ece11b02bc210c705a04ece11200a0000c705784ece1100000000c7057c4ece1100000000c705944ece11', 'mask': 'ffffff00000000ffffffffffff00000000ffffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}, {'pattern': '50000000c705844fce11f0818a10c7056004ee10744ece11c7056404ee1005000000c7056804ee1000000000c7056c04ee10dc2cc21066c7057004ee100000c3', 'mask': 'ffffffffffff0000000000000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff0000000000000000ffffff00000000ffffff', 'operand': 20}], 'netprop:m_hRagdoll': [{'pattern': '05040dd01100b9102e9b10a3140dd01185c9c705f40cd0115cfbc910b8102e9b10c705200dd011881600000f44c6c705f80cd01100000000c705fc0cd0110000', 'mask': 'ff00000000ffff00000000ff00000000ffffffff0000000000000000ff00000000ffff00000000ffffffffffffffffff00000000ffffffffffff00000000ffff', 'operand': 20}, {'pattern': '00000000c7059c0cd01170818a10e86967efffb9f40cd011c705b80cd01140fbc910c705e40cd0112c160000bed0819110c705bc0cd01101000000c705c00cd0', 'mask': 'ffffffffffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffff00000000ffff00000000ffffffffffff000000', 'operand': 20}], 'netprop:m_bRedraw': [{'pattern': '00000000c705c83dd01170818a10e88591ebffb9203ed011c705e43dd0115871be10c705103ed01100000000c705e83dd01106000000c705ec3dd01100000000', 'mask': 'ffffffffffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffff', 'operand': 20}, {'pattern': '0c3ed01178fd0611e83f91ebffb95c3ed011c705203ed011f004cb10c7054c3ed011a80b0000c705243ed01100000000c705283ed01100000000c705403ed011', 'mask': '0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}], 'netprop:m_fThrowTime': [{'pattern': '00000000c705403ed01190808a10e80391ebffb9983ed011c7055c3ed011fc04cb10c705883ed011a90b0000c705603ed01100000000c705643ed01100000000', 'mask': 'ffffffffffff0000000000000000ffffffffffff00000000ffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffff', 'operand': 20}, {'pattern': '000000c7057c3ed01190808a10e8c790ebffc705983ed011c804cb10c705c43ed011ac0b0000c7059c3ed01101000000c705a03ed01100000000c705b83ed011', 'mask': 'ffffffffff0000000000000000ffffffffffffff0000000000000000ffff00000000ffffffffffff00000000ffffffffffff00000000ffffffffffff00000000', 'operand': 20}]}}, 'engine.dll': {'anchors': {'local_index': [{'pattern': '10ff502884db7413a1c0b98210b9c0b98210ff3530238d10ff50288b068bce68004000008b4008ffd084c07475e8db39050084c0756c833db46e70100074128b', 'mask': '00ffffffffffffffff00000000ff00000000ffff00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000ffffffff', 'operand': 20}, {'pattern': '0f114610e8995725008b0dc002901185c97428a130238d108b114050ff520c85c074188b108bc8ff52248b08894e088b4804894e0c8b4008894610f30f104610', 'mask': 'ffffffffffffffffffffff00000000ffffffffff00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}], 'signon': [{'pattern': 'c3ccccccccccccccb804000000e8961c4a00833dc4228d10068b411c7c12f30f2c4830e890a90e00890424db042459c3d9403059c3cccccc64a1000000006aff', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}, {'pattern': '442404f30f110424837834000f84a9000000833dc4228d10060f8c9c000000a130497510b9304975108b4044ffd0d82c24a1ccb58210f30f104830d91c24f30f', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffffffffffffffff00000000ff00000000ffffffffffffffffff00000000ffffffffffffffffffff', 'operand': 20}], 'view_angles': [{'pattern': '0f28ca8b0dd0029011f30f114c240cf30f5cca68642c9110f30f580d682c9110f30f110d682c91108b01ff5034f30f1044240cf30f1105882c9110f30f104424', 'mask': 'ffffffffff00000000ffffffffffffffffffffff00000000ffffffff00000000ffffffff00000000ffffffffffffffffffffffffffffff00000000ffffffffff', 'operand': 20}, {'pattern': 'c20400cccccccccccccccccc8b442404f30f1005642c9110f30f1100f30f1005682c9110f30f114004f30f10056c2c9110f30f114008c20400cccccc568b7424', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffffffffffffffff00000000ffffffffffffffffff00000000ffffffffffffffffffffffffffffff', 'operand': 20}], 'render': [{'pattern': 'ccccccb820747010c3ccccccccccccccccccccb9c0eba310a1c0eba310ff6034ccccccb9c0eba310a1c0eba310ff6030cccccca140f2a310485678218b3534f2', 'mask': 'ffffffff00000000ffffffffffffffffffffffff00000000ff00000000ffffffffffffff00000000ff00000000ffffffffffffff00000000ffffffffffff0000', 'operand': 20}, {'pattern': '747010c3ccccccccccccccccccccb9c0eba310a1c0eba310ff6034ccccccb9c0eba310a1c0eba310ff6030cccccca140f2a310485678218b3534f2a3108bc88b', 'mask': '000000ffffffffffffffffffffffff00000000ff00000000ffffffffffffff00000000ff00000000ffffffffffffff00000000ffffffffffff00000000ffffff', 'operand': 20}], 'level_name': [{'pattern': 'cccccccccccccccccc803dec0f801000750d803d34238d10000f849f000000833d006f701001751e8b0de09b6e108b018b4018ffd084c00f85810000008b4c24', 'mask': 'ffffffffffffffffffffff00000000ffffffffff00000000ffffffffffffffffff00000000ffffffffff00000000ffffffffffffffffffffffffffffffffffff', 'operand': 20}, {'pattern': '69f9ff83c4105ec3cccccccccccccccccccc803d34238d1000742f833d006f701001751a8b0de09b6e108b018b4018ffd084c075158b4c2404e93452faff6a01', 'mask': 'ffffffffffffffffffffffffffffffffffffffff00000000ffffffffff00000000ffffffffff00000000ffffffffffffffffffffffffffffffffffffffffffff', 'operand': 20}]}}}


# host_data.py
# Only the command/weapon database is compressed JSON; no code is encoded.
import base64, json, zlib
DATA = json.loads(zlib.decompress(base64.b64decode('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')))


# host_core.py
"""CSO2 host backend, with process discovery and verified x86 layout adapters.

No game operations run at import. The UI worker owns every game handle.
"""
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

class NotReady(RuntimeError): pass

class PlayerUnavailable(NotReady):
    """A temporary per-entity lifecycle condition, not a layout or I/O error."""
    pass

class ConnectionProblem(NotReady):
    def __init__(self,message,code,requires_admin=False):
        super().__init__(message);self.code=code;self.requires_admin=requires_admin

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
        row=kind();row.dwSize=C.sizeof(row);C.set_last_error(0);ok=f(handle,C.byref(row))
        while ok:
            yield kind.from_buffer_copy(row)
            C.set_last_error(0);ok=n(handle,C.byref(row))
        error=C.get_last_error()
        if error not in (0,18):raise C.WinError(error)
    finally:k.CloseHandle(handle)

def game_pids():
    return [e.th32ProcessID for e in snapshot_entries(2,0,PROCESSENTRY32W,'Process32FirstW','Process32NextW') if e.th32ProcessID>4 and e.th32ProcessID!=os.getpid()]

def modules(pid):
    for attempt in range(3):
        try:return {e.szModule.lower():(e.modBaseAddr,e.modBaseSize,Path(e.szExePath)) for e in snapshot_entries(0x18,pid,MODULEENTRY32W,'Module32FirstW','Module32NextW')}
        except OSError as ex:
            if getattr(ex,'winerror',None)!=24 or attempt==2:raise
            time.sleep(.015)

def process_info(pid):
    """Limited-query rights work across UAC levels; never request game write access."""
    k=C.WinDLL('kernel32',use_last_error=True);adv=C.WinDLL('advapi32',use_last_error=True)
    k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
    k.CloseHandle.argtypes=[W.HANDLE]
    k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)];k.QueryFullProcessImageNameW.restype=W.BOOL
    adv.OpenProcessToken.argtypes=[W.HANDLE,W.DWORD,C.POINTER(W.HANDLE)];adv.OpenProcessToken.restype=W.BOOL
    adv.GetTokenInformation.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)];adv.GetTokenInformation.restype=W.BOOL
    handle=k.OpenProcess(0x1000,False,pid)
    if not handle:return {}
    result={};token=W.HANDLE()
    try:
        length=W.DWORD(32768);buffer=C.create_unicode_buffer(length.value)
        if k.QueryFullProcessImageNameW(handle,0,buffer,C.byref(length)):result['path']=Path(buffer.value)
        if adv.OpenProcessToken(handle,8,C.byref(token)):
            value=W.DWORD();used=W.DWORD()
            if adv.GetTokenInformation(token,20,C.byref(value),C.sizeof(value),C.byref(used)):result['elevated']=bool(value.value)
    finally:
        if token:k.CloseHandle(token)
        k.CloseHandle(handle)
    return result

def is_admin():
    try:return bool(C.windll.shell32.IsUserAnAdmin())
    except (OSError,AttributeError):return False

def image_role(path):
    """Disk layout is a diagnostic hint only, never enough to enable a feature."""
    if not path:return None
    directory=Path(path).parent
    def pair(folder):return all((folder/name).is_file() for name in ('client.dll','engine.dll'))
    if pair(directory):return 'client'
    if any(pair(directory/name) for name in ('Bin','bin32','win32')):return 'launcher'
    return None

def discover_client(module_loader,preferred=None,cancelled=None,probe=None):
    candidates=[];unavailable={};launchers=[]
    for pid in game_pids():
        if cancelled and cancelled():raise ConnectionProblem('连接请求已取消','cancelled')
        failure=None
        try:mods=module_loader(pid)
        except (OSError,MemoryError) as ex:mods={};failure=ex
        if all(name in mods for name in ('client.dll','engine.dll')):
            candidates.append((pid,mods));continue
        info=process_info(pid) if failure else {}
        path=info.get('path') or next((v[2] for name,v in mods.items() if name.endswith('.exe')),None)
        role=image_role(path)
        if role=='launcher':launchers.append(pid)
        if role!='client':continue
        directory=Path(path).parent
        placeholder={name:(0,0,directory/name) for name in ('client.dll','engine.dll')}
        candidates.append((pid,placeholder))
        error=getattr(failure,'winerror',None)
        if error==5:
            elevate=info.get('elevated') is True and not is_admin()
            tip='；点击“管理员连接”，在 Windows 提示中允许后重连' if elevate else '；请检查进程读取权限'
            unavailable[pid]=ConnectionProblem(f'已发现游戏 PID {pid}，但 Windows 拒绝读取模块（错误 5）'+tip,'access_denied',elevate)
        elif failure:
            unavailable[pid]=ConnectionProblem(f'已发现游戏 PID {pid}，读取模块失败（Windows 错误 {error or "未知"}）','module_read_failed')
        else:
            missing=' / '.join(name for name in ('client.dll','engine.dll') if name not in mods)
            unavailable[pid]=ConnectionProblem(f'已发现游戏 PID {pid}，正在等待加载 {missing}；稍后重新连接','loading')
    if not candidates:
        if launchers:raise ConnectionProblem('只检测到启动器，尚未检测到游戏客户端；请先在启动器里启动游戏','launcher_only')
        raise ConnectionProblem('未发现游戏客户端进程；请先启动游戏，再点击连接游戏','not_running')
    available=[item for item in candidates if item[0] not in unavailable]
    if not available:
        # Preserve permission/loading diagnostics without mixing placeholders
        # into selection of a client that is already readable.
        raise next(iter(unavailable.values()))
    candidate=choose_candidate(available,preferred or Path.cwd(),probe=probe if len(available)>1 else None)
    if candidate[0] in unavailable:raise unavailable[candidate[0]]
    return candidate

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
    def write_code_byte(self,address,expected,value):
        """Replace one checked byte and flush the cache; never patch a whole live instruction."""
        if len(expected)!=1 or len(value)!=1:raise ValueError('代码更新必须为单字节')
        if self.read(address,1)!=expected:raise NotReady('购买菜单代码已变化，已取消更新')
        k=self.k
        k.VirtualProtectEx.argtypes=[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,C.POINTER(W.DWORD)];k.VirtualProtectEx.restype=W.BOOL
        k.FlushInstructionCache.argtypes=[W.HANDLE,C.c_void_p,C.c_size_t];k.FlushInstructionCache.restype=W.BOOL
        handle=k.OpenProcess(0x0438,False,self.pid)
        if not handle:raise C.WinError(C.get_last_error())
        old=W.DWORD();protected=False
        try:
            if not k.VirtualProtectEx(handle,address,1,0x40,C.byref(old)):raise C.WinError(C.get_last_error())
            protected=True
            if self.read(address,1)!=expected:raise NotReady('购买菜单代码已变化，已取消更新')
            count=C.c_size_t();buffer=C.create_string_buffer(value)
            if not k.WriteProcessMemory(handle,address,buffer,1,C.byref(count)) or count.value!=1:raise C.WinError(C.get_last_error())
            if not k.FlushInstructionCache(handle,address,1):raise C.WinError(C.get_last_error())
            if self.read(address,1)!=value:raise NotReady('购买菜单代码读回不一致')
        finally:
            try:
                if protected:
                    unused=W.DWORD()
                    if not k.VirtualProtectEx(handle,address,1,old.value,C.byref(unused)):raise C.WinError(C.get_last_error())
            finally:k.CloseHandle(handle)
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

def bot_stop_target(text):
    parts=console_segments(text)
    if len(parts)==1 and len(parts[0])==2 and parts[0][0].casefold()=='bot_stop' and parts[0][1] in ('0','1'):
        return int(parts[0][1])
    return None

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

def player_action_stub(remote,guards,call,code_size=512):
    """x86 thread entry; revalidate entity identities immediately before action."""
    code=bytearray(b'\x60');fixups=[]
    for address,expected in guards:
        code+=b'\x81\x3d'+struct.pack('<II',address,expected)+b'\x0f\x85\0\0\0\0';fixups.append(len(code)-4)
    code+=call(remote)+b'\x61\xb8\x01\0\0\0\xc2\x04\0'
    failed=len(code);code+=b'\x61\x31\xc0\xc2\x04\0'
    for at in fixups:struct.pack_into('<i',code,at,failed-at-4)
    if len(code)>code_size:raise ValueError('原生操作过大')
    return bytes(code).ljust(code_size,b'\0')


TP_CODE=0x1000
TP_SELECTED=0x1080
TP_STATUS=0x1090
TP_ZERO=0x10b0
TP_DELTA=0x10c0
TP_MATRIX=0x10d0
TP_ABS=0x1100
TP_OBJECTS=0x1120
TP_SIZE=0x1200


def teleport_payload(origin,corpse=None):
    data=bytearray(TP_SIZE-TP_CODE)
    struct.pack_into('<3f',data,TP_SELECTED-TP_CODE,*origin)
    struct.pack_into('<f',data,TP_ABS-TP_CODE,48.)
    if corpse:struct.pack_into('<'+'I'*len(corpse['objects']),data,TP_OBJECTS-TP_CODE,*corpse['objects'])
    return data


def teleport_code(remote,teleports,body=None,body_edict=None,anchor=None,corpse=None):
    code=bytearray()
    selected=remote+TP_SELECTED
    status=remote+TP_STATUS
    def call(this,method,args=()):
        result=bytearray()
        for arg in reversed(args):result+=b'\x68'+struct.pack('<I',arg)
        return result+b'\xb9'+struct.pack('<I',this)+b'\xb8'+struct.pack('<I',method)+b'\xff\xd0'
    if anchor:
        # Sample the root physics body on the game frame, not a stale network
        # origin or the dead player's hidden server entity.
        code+=call(anchor['rag'],anchor['get_origin'])
        for i in range(3):
            if i==0:
                code+=b'\xf3\x0f\x10\x40\x00\xf3\x0f\x58\x05'+struct.pack('<I',remote+TP_ABS)
                code+=b'\xf3\x0f\x11\x05'+struct.pack('<I',selected)
            else:code+=b'\x8b\x50'+bytes([i*4])+b'\x89\x15'+struct.pack('<I',selected+i*4)
    if corpse:
        code+=call(corpse['rag'],corpse['get_origin'])
        for i in range(3):
            code+=b'\xf3\x0f\x10\x05'+struct.pack('<I',selected+i*4)
            code+=b'\xf3\x0f\x5c\x40'+bytes([i*4])
            code+=b'\xf3\x0f\x11\x05'+struct.pack('<I',remote+TP_DELTA+i*4)
            code+=b'\xf3\x0f\x58\x05'+struct.pack('<I',corpse['address']+0x300+i*4)
            code+=b'\xf3\x0f\x11\x05'+struct.pack('<I',remote+TP_ABS+i*4)
        code+=b'\xbe'+struct.pack('<I',remote+TP_OBJECTS)+b'\xbf'+struct.pack('<I',len(corpse['objects']))
        loop=len(code)
        # Get/SetPositionMatrix preserves each bone's exact orientation.
        code+=b'\x8b\x1e\x68'+struct.pack('<I',remote+TP_MATRIX)+b'\x8b\xcb\xb8'+struct.pack('<I',corpse['get_matrix'])+b'\xff\xd0'
        for i in range(3):
            code+=b'\xf3\x0f\x10\x05'+struct.pack('<I',remote+TP_MATRIX+12+16*i)
            code+=b'\xf3\x0f\x58\x05'+struct.pack('<I',remote+TP_DELTA+4*i)
            code+=b'\xf3\x0f\x11\x05'+struct.pack('<I',remote+TP_MATRIX+12+16*i)
        code+=b'\x6a\x01\x68'+struct.pack('<I',remote+TP_MATRIX)+b'\x8b\xcb\xb8'+struct.pack('<I',corpse['set_matrix'])+b'\xff\xd0'
        code+=b'\x68'+struct.pack('<I',remote+TP_ZERO)+b'\x68'+struct.pack('<I',remote+TP_ZERO)+b'\x8b\xcb\xb8'+struct.pack('<I',corpse['set_velocity'])+b'\xff\xd0'
        code+=b'\x8b\xcb\xb8'+struct.pack('<I',corpse['wake'])+b'\xff\xd0\x83\xc6\x04\x4f\x0f\x85'
        code+=struct.pack('<i',loop-len(code)-4)
        code+=call(corpse['address'],corpse['set_origin'],(remote+TP_ABS,))
        code+=call(corpse['rag'],corpse['get_origin'])
    for address,method in teleports:
        code+=b'\xb9'+struct.pack('<I',address)+b'\x68'+struct.pack('<I',remote+TP_ZERO)+b'\x6a\x00\x68'+struct.pack('<I',selected)
        code+=b'\xb8'+struct.pack('<I',method)+b'\xff\xd0'
    if body:
        for i in range(3):
            code+=b'\xa1'+struct.pack('<I',selected+i*4)+b'\xa3'+struct.pack('<I',body+0x71c+i*4)
        code+=b'\x81\x0d'+struct.pack('<I',body_edict)+b'\x01\x01\x00\x00'
    code+=b'\xc7\x05'+struct.pack('<II',status,1)
    return bytes(code)

def player_frame_stub(control):
    # GameFrame owns native entity and UI calls. Preserve the caller state,
    # chain the existing callback, and consume at most one queued request.
    code=bytearray.fromhex('558bec81ec2002000083e4f00fae04249c60ff7508b8')
    code+=struct.pack('<I',control)+bytes.fromhex('ff5014bb')+struct.pack('<I',control)
    code+=bytes.fromhex('837b04010f85');skip=len(code);code+=b'\0'*4
    code+=bytes.fromhex('b801000000ba02000000f00fb153080f85');busy=len(code);code+=b'\0'*4
    code+=bytes.fromhex('6a00ff530c894310c7430803000000')
    end=len(code);code+=bytes.fromhex('619d0fae0c248be55dc20400')
    for at in (skip,busy):struct.pack_into('<i',code,at,end-at-4)
    return bytes(code)

class PlayerActionQueue:
    def __init__(self,backend):
        self.b=backend;self.m=backend.mem;self.k=self.m.k;self.handle=None;self.address=0;self.pending=False;self.installed=False;self.result_offset=None
        specs={'OpenProcess':(W.HANDLE,[W.DWORD,W.BOOL,W.DWORD]),
            'VirtualAllocEx':(C.c_void_p,[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,W.DWORD]),
            'VirtualProtectEx':(W.BOOL,[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,C.POINTER(W.DWORD)]),
            'FlushInstructionCache':(W.BOOL,[W.HANDLE,C.c_void_p,C.c_size_t])}
        for name,(ret,args) in specs.items():fn=getattr(self.k,name);fn.restype=ret;fn.argtypes=args
        s=backend.server;slot=s+0x858710;original=s+0x3aa4d0;self.slot=slot;self.original=original
        checks=((s+0x3a80f0,b'\xb8'+struct.pack('<I',s+0xa0a37c)+b'\xc3'),
            (s+0xa0a37c,struct.pack('<I',s+0x8586f8)),
            (original,b'\x83\xec\x10\x80\x3d'+struct.pack('<I',s+0xc58fe8)+b'\0'),
            (s+0x3aa645,bytes.fromhex('c20400')))
        if any(self.m.read(at,len(value))!=value for at,value in checks):raise NotReady('游戏主线程回调尚未验证')
        self.previous=self.checked_previous()
        self.handle=self.k.OpenProcess(0x0438,False,self.m.pid)
        if not self.handle:raise C.WinError(C.get_last_error())
        try:
            self.address=self.k.VirtualAllocEx(self.handle,None,16384,0x3000,0x40)
            if not self.address:raise C.WinError(C.get_last_error())
            self.control=self.address+1024;self.request=self.address+4096
            self.write(self.control,b'HPA1'+struct.pack('<5I',0,0,self.request,0,self.previous))
            self.write(self.address,player_frame_stub(self.control))
            if not self.k.FlushInstructionCache(self.handle,self.address,1024):raise C.WinError(C.get_last_error())
        except Exception:self.close();raise
    def checked_previous(self):
        previous=self.m.u32(self.slot)
        # Existing pose callbacks have a stable chaining header and retain
        # their pages until process exit. Three verified revisions are
        # accepted; unknown owners remain blocked.
        if previous!=self.original:
            header=self.m.read(previous,14)
            if header[:5]!=bytes.fromhex('5589e583ec') or header[6:10]!=bytes.fromhex('535657bb'):raise NotReady('游戏帧回调由其他工具占用')
            data=struct.unpack_from('<I',header,10)[0]
            magic=self.m.read(data,4)
            layouts={
                b'SP23':(353,'8ff907c5b45100eec98b0319d173aae4c6d7df097408966e549ac194c67fde3a'),
                b'SP26':(660,'d510c5fd78f673746cdc76514f5753e9e2844c74e3b1ddd6005a8af396127377'),
                b'SQ27':(1311,'83542e031ec164fa0fa5425c8302b3339965f66e9771e9944bc356482759f120'),
            }
            layout=layouts.get(magic)
            if layout is None:raise NotReady('当前游戏帧回调不能安全串接')
            size,digest=layout
            code=bytearray(self.m.read(previous,size));code[10:14]=b'\0\0\0\0'
            if hashlib.sha256(code).hexdigest()!=digest:raise NotReady('当前游戏帧回调字节布局不匹配')
            if struct.unpack('<3I',self.m.read(data+0x20,12))!=(self.b.server,self.slot,self.original):raise NotReady('当前游戏帧回调签名不匹配')
            if magic!=b'SP23' and self.m.read(data+0x40,8)!=struct.pack('<II',previous+8192,self.b.server+0x2f7ce0):raise NotReady('当前游戏帧回调布局不匹配')
        return previous
    def swap(self,expected,value):
        old=W.DWORD()
        if not self.k.VirtualProtectEx(self.handle,self.slot,4,4,C.byref(old)):raise C.WinError(C.get_last_error())
        try:
            if self.m.u32(self.slot)!=expected:raise NotReady('游戏帧回调发生变化')
            self.write(self.slot,struct.pack('<I',value))
        finally:
            unused=W.DWORD();self.k.VirtualProtectEx(self.handle,self.slot,4,old.value,C.byref(unused))
    def detach(self):
        self.write(self.control+4,struct.pack('<I',0))
        if self.installed and self.m.u32(self.slot)==self.address:self.swap(self.address,self.previous)
        self.installed=False
    def write(self,address,data):
        n=C.c_size_t();buf=C.create_string_buffer(data)
        if not self.k.WriteProcessMemory(self.handle,address,buf,len(data),C.byref(n)) or n.value!=len(data):raise C.WinError(C.get_last_error())
    def poll(self):
        if not self.pending:return True
        status=self.m.u32(self.control+8)
        if status!=3:
            if time.monotonic()-self.pending_at>2 and status==1:self.detach();self.pending=False;raise NotReady('玩家操作等待游戏帧超时，已取消')
            return False
        self.detach();self.pending=False;self.write(self.control+8,struct.pack('<I',0))
        if self.m.u32(self.control+16)!=1:raise NotReady('玩家身份已变化，本次操作已取消')
        if self.result_offset is not None and self.m.u32(self.request+self.result_offset)!=1:
            self.result_offset=None
            raise NotReady('原生传送未完成')
        self.result_offset=None
        return True
    def submit_native(self,build,result_offset=None):
        if not self.poll():raise NotReady('上一项玩家操作尚未结束')
        data=build(self.request)
        if len(data)>8192:raise ValueError('原生操作参数过大')
        self.write(self.request,data)
        self.result_offset=result_offset
        if not self.k.FlushInstructionCache(self.handle,self.request,len(data)):raise C.WinError(C.get_last_error())
        self.previous=self.checked_previous();self.write(self.control+20,struct.pack('<I',self.previous))
        self.write(self.control+4,struct.pack('<II',1,1));self.pending_at=time.monotonic();self.pending=True
        try:self.swap(self.previous,self.address);self.installed=True
        except Exception:self.write(self.control+4,struct.pack('<I',0));self.pending=False;raise
    def close(self):
        try:
            if self.address:self.detach()
        finally:
            # Another callback may be chained above this one or executing it.
            # Leave disabled forwarding code alive until the game exits.
            if self.handle:self.k.CloseHandle(self.handle);self.handle=None

def vote_callback(backend):
    """Locate the game's own kickreport.call.send registration in this client."""
    module=backend.mods['client.dll'];image=module_image(module[2]);string=b'kickreport.call.send\0'
    raw_at=image.raw.find(string)
    if raw_at<0 or image.raw.find(string,raw_at+1)>=0:raise NotReady('投票入口名称不唯一或缺失')
    section=next((s for s in image.sections if s['offset']<=raw_at<s['offset']+s['stored']),None)
    if section is None:raise NotReady('投票入口不在客户端映像中')
    name_rva=section['rva']+raw_at-section['offset'];hits=[]
    for s in image.sections:
        if not s['flags']&0x20000000:continue
        raw=image.raw[s['offset']:s['offset']+s['stored']];needle=b'\x68'+struct.pack('<I',image.image_base+name_rva);start=0
        while (start:=raw.find(needle,start))>=0:
            chunk=raw[start:start+48]
            match=re.search(rb'\x8b\x07\x68(.{4})\x51\x8b\xcf\xff\x50\x04',chunk,re.DOTALL)
            if match:
                rva=struct.unpack('<I',match[1])[0]-image.image_base
                if any(t['flags']&0x20000000 and t['rva']<=rva<t['rva']+t['stored'] for t in image.sections):
                    at=s['rva']+start;live=backend.mem.read(module[0]+at,len(chunk))
                    if live[:5]==b'\x68'+struct.pack('<I',module[0]+name_rva) and live[match.start():match.start()+3]==b'\x8b\x07\x68' and struct.unpack_from('<I',live,match.start()+3)[0]==module[0]+rva:
                        hits.append(module[0]+rva)
            start+=5
    if len(set(hits))!=1:raise NotReady('当前客户端投票处理函数尚未确认')
    callback=hits[0]
    if backend.mem.read(callback,6)!=bytes.fromhex('558bec83e4f8'):raise NotReady('投票参数调用约定不匹配')
    return callback

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
    damage_mode:int|None=None  # Sampled game state; None means not verified.
    ghost_alpha:int|None=None  # Only sampled for T players in verified ghost mode.

@dataclass
class MutationMachine:
    key:PlayerKey
    skill:int
    enabled:bool
    pending:bool

# Datamap and SendProp offsets were checked in the loaded server module.
FIELDS=(
    (0x9c0180,'m_takedamage',0xf9,4),
    (0x9be610,'m_flModelScale',0x37c,4),
    (0x9f4b50,'m_flScale',0x6ec,4),
    (0x9c01e8,'m_iHealth',0xf4,4),(0x9c01b4,'m_iMaxHealth',0xf0,4),(0x9c014c,'m_lifeState',0xf8,4),
    (0x9f4298,'m_iAccount',0x1c3c,4),(0xcadd40,'m_iMaxAccount',0x1c40,24),
    (0x9ddee8,'m_szNetname',0xed0,4),(0x9f4b84,'m_flHeadScale',0x6f0,4),(0x9f4bb8,'m_flBodyScale',0x6f4,4),
    (0x9bf3c8,'m_iClip1',0x54c,4),(0x9bf394,'m_iPrimaryAmmoType',0x53c,4),
    (0x9bef4c,'m_hMyWeapons',0x7ac,4),(0x9bef80,'m_hActiveWeapon',0x86c,4),
    (0xc7a1f8,'m_iAmmo',0x75c,24),(0x9f71b8,'m_iUserFlag',0x6e0,4),
)
GHOST_FIELDS=((0x9f3fc0,'m_infoGhost',0x1290,4),
              (0x9f4870,'m_fTimeToGhost',0x1c,4),
              (0x9f48a4,'m_u1MinAlpha',0x20,4),
              (0x9f48d8,'m_u1MaxAlpha',0x21,4),
              (0x9f490c,'m_u1MovingAlpha',0x22,4),
              (0x9bff44,'m_clrRender',0x88,4))
GHOST_VISIBLE=struct.pack('<f3B',0.1,255,255,255)
GHOST_SET_SIGNATURE=bytes.fromhex('558bec51894dfc8b45fcf30f104508f30f1180ac1200008b4dfc8a55108891b11200008b45fc8a4d0c8888b01200008b55fc8a45148882b21200008be55dc21000')

HEROES_CODE=((6405856, 144, '33519a646f21bed5402761bb9d0dd6891179f4a07f88141a44ac0699c14bd081', (33, 58, 108, 127)), (6406208, 13, 'c57164f3758b6e6622b814704cb76ef1acd04a6d431e721aa48ca9c7438f7dc8', ()), (6407104, 256, 'ff4876693b06dd4dac1cf9357a3cd07490f9abda57126aefc8d6841bc1b6e653', (16, 51, 85, 91, 109, 127, 141, 172, 186, 198)), (6407360, 384, 'dbb2ce174e5f15b410757e95ff7d5cd4c9045e255cd05ff38d1f4f3923700c29', (9, 73, 119, 127, 188, 231, 257, 275, 309, 345)), (6407744, 592, '4a9fdb1f0a7b35905383afcd6423b9606f37ead61e989bf2c1e6cebae5fb07b9', (15, 46, 113, 127, 162, 178, 187, 193, 222, 235, 241, 259, 304, 354, 372, 384, 399, 424, 431, 457, 473, 495, 506, 561)), (6408336, 269, 'f50fa201839cd48d83bdd0176cbe0cdbe0a01c5f9f54cefba93af079bc6fb14f', (15, 81, 120, 157, 183, 234)), (6408608, 85, '629047895ce04f039b63e42d5464ced038321c7914866d9e404a286eb185d48a', (18, 32, 57, 70)), (6408704, 672, 'f1d2245ce1520b2f3b987442be1131956bb2cf4c757c54103ef577f630f92c89', (9, 55, 102, 157, 171, 206, 222, 231, 237, 266, 279, 285, 303, 370, 480, 487, 535, 542, 572, 588, 616, 627)), (6409456, 160, '345089b3ad553aa0edf53f20beaabe53c2fce0fcd43b5d150e70c39a605522c8', (1, 23, 32, 37, 60, 65, 88, 93, 116, 121, 134, 139)), (6413216, 98, 'f7d3794d160bd6728a251c0c647a36afc96b4ceba1baae3f034a601e44359d40', (18, 59)), (6413328, 150, '39c70f7207773181301900a88caaa69c3df0aab53eeab7f958060e077715d89a', (9, 89)), (6413648, 501, 'b0af23466468417303a708cbb273d0f3ddc85f841aacc309d77d4026b37def6b', (37, 163, 389)), (754416, 98, '962c03d806d155c17a6d94bdffd6f06caff74f62772e9c100118217bd5232968', (27, 63)), (6448752, 178, '1634a816e17a85090db9a2b86a488286586ef8fdb44972ad56a04baabe9e9f73', (43, 97)), (6539456, 282, '1647a89ad4ce98d9d9413e658e8e5ae93635f93d83aacf6c8abbf73c0b3846ce', (9, 57, 102, 107, 189)), (6372832, 340, '2ce4e741782202df65dc3c235c9f68a698c7e43a14a8f234d608d1950aaaca99', (9, 46, 51, 108, 115, 203, 210, 232, 241, 311)))

# Heroes adapter: native server paths verified against the shipped server.dll.
HEROES_UPGRADE_CODE=((5517488, 222, '2feab62e57bf4decf9b0e510f0be0a1a5ad1b2d49c2e8fb69ea69794cc12f5f6', (6, 149)), (5517712, 265, '3b024b87684aa28807d925239cf40aef285863692c57d1f5cc40526562048881', (6, 192)), (616976, 6, '7a59f004f8bd8c5ad012968d8e9bcba95d54a84254713d600522a21c099944e0', (1,)), (6412944, 47, 'ca70a57abbf88b6da32668b57d65d41fc5153ff1e18a54c03fec8b2447a461cd', ()), (581312, 77, 'a299da091c8a901e9786bbb991df6a0d302634bc85979f3b283963cb7bc3d89d', ()), (698320, 87, '7b37cbb3f43142e6be422c22474ac45030ff19555980c9a7b1ff2cf9ff7e4b35', ()), (860288, 50, '26e96c9ebdb591639825bc06ac3876a0150ef891b2c820aa0cc6fcb01a970062', ()), (698288, 7, '77f985978f92a713f60f849133828747b08eb10d3b8ef6c6a5d17d1d3deaf962', ()), (712624, 50, 'cbea5c2d6f3c9a82d0f29ed58de51d0d7c02a8c0ce4986eb0254c0596d86ed8c', ()))
HEROES_STATES={0x8f3630:1,0x8f3654:2,0x8f366c:3,0x8f3618:4}
HEROES_DAMAGE=('cso2mon_movezone_triggerdam','cso2mon_movezone_triggerdam_boss')


def heroes_call(this,method,*args):
    return b''.join(b'\x68'+struct.pack('<I',arg & 0xffffffff) for arg in reversed(args))+b'\xb9'+struct.pack('<I',this)+b'\xb8'+struct.pack('<I',method)+b'\xff\xd0'


def heroes_phase_event(server,previous,current,wave):
    # Match the native CreateEvent / SetInt / FireEvent call chain. EBX owns
    # the event until FireEvent; the outer request preserves all registers.
    code=bytearray(b'\x8b\x0d'+struct.pack('<I',server+0xc59050))
    code+=b'\x6a\x00\x68'+struct.pack('<I',server+0x8f2d30)+b'\x8b\x01\xff\x50\x18\x89\xc3\x85\xdb\x0f\x84'
    skip=len(code);code+=bytes(4)
    for name,value in ((0x8f2d24,previous),(0x8f2d18,current),(0x8f2cb8,wave)):
        code+=b'\x68'+struct.pack('<I',value)+b'\x68'+struct.pack('<I',server+name)+b'\x89\xd9\x8b\x03\xff\x50\x28'
    code+=b'\x8b\x0d'+struct.pack('<I',server+0xc59050)+b'\x6a\x00\x53\x8b\x01\xff\x50\x1c'
    struct.pack_into('<i',code,skip,len(code)-skip-4)
    return bytes(code)


def heroes_native_payload(remote,server,sample,guards,action,target=None):
    rules=sample['rules'];phase=sample['phase'];wave=sample['wave']
    def body(address):
        if action=='kill':return heroes_call(server+0xc23340,server+0x63c8c0)
        if action=='no_wait':
            if phase not in (2,4):raise NotReady('当前没有准备/波间等待')
            offset=0x18 if phase==2 else 0x20
            return b'\xc7\x05'+struct.pack('<II',sample['fsm']+offset,0)
        if action=='finish':
            code=heroes_phase_event(server,phase,4,wave)
            code+=heroes_call(rules,server+0x61deb0)  # Exit disables old spawn IDs; POST kills survivors.
            code+=heroes_call(rules,server+0x61dba0,0)
            # POST still owns revival, wave advance and final victory. Only
            # its waiting interval is shortened; IN's failure timer is intact.
            return code+b'\xa1'+struct.pack('<I',rules+0x464)+b'\xc7\x40\x20\0\0\0\0'
        if action!='jump':raise ValueError('未知洛奇操作')
        code=heroes_call(rules,server+0x61dd50)  # PRE removes IN event listener and disables old spawning.
        code+=heroes_call(server+0xc23340,server+0x63c8c0)
        code+=heroes_call(rules,server+0x61dba0,0)
        # READY/POST exit can increment the wave. Compute the delta AFTER
        # exit, on the game frame, and use the native network-dirty helper.
        code+=b'\xb8'+struct.pack('<I',target)+b'\x2b\x05'+struct.pack('<I',rules+0x48c)
        code+=b'\xa3'+struct.pack('<I',address+2048)
        code+=heroes_call(rules+0x48c,server+0xb82f0,address+2048)
        code+=heroes_phase_event(server,2,3,target)
        return code+heroes_call(rules,server+0x61ddf0)
    return player_action_stub(remote,guards,body,code_size=2048)+bytes(16)



def is_tv_player(player):
    return re.sub(r'[^a-z0-9]','',player.name.casefold()) in ('cso2tv','sourcetv','hltv')


def heroes_upgrade_payload(remote,server,key,field,level,guards):
    if field not in ('atk','hp'):raise ValueError('未知强化类型')
    def body(_):
        code=heroes_call(key.address,server+(0x5430b0 if field=='atk' else 0x543190),level)
        if field=='hp':
            # Native HP upgrades preserve missing health. A downward selection
            # must not leave a live entity with negative HP and no death event.
            code+=heroes_call(key.address,server+0xaa7b0)
            patch=heroes_call(key.address,server+0xadfb0,1)
            code+=b'\x83\xf8\x01\x7d'+bytes([len(patch)])+patch
        return code
    return player_action_stub(remote,guards,body,code_size=2048)


HERO_MODELS=(('Evy · 01', 'models/player/mabi_evy/mabi_evy01.mdl'), ('Evy · 02', 'models/player/mabi_evy/mabi_evy02.mdl'), ('Hurk · 01', 'models/player/mabi_hurk/mabi_hurk01.mdl'), ('Hurk · 02', 'models/player/mabi_hurk/mabi_hurk02.mdl'), ('Kay · 01', 'models/player/mabi_kay/mabi_kay01.mdl'), ('Kay · 02', 'models/player/mabi_kay/mabi_kay02.mdl'), ('Lynn · 01', 'models/player/mabi_lynn/mabi_lynn01.mdl'))
HERO_MODEL_CODE={'server.dll': ((6140992, 18, '00fe3ef33565d303c5493e4621f0cd6fa92b9eb63262ca3120ee2bec7e3ed075', (2,)), (5366640, 2616, '5f557bc9fb265b94180ad9b83f42f1a3855573f540055404136f979f846401be', (6, 87, 95, 186, 194, 280, 288, 377, 385, 415, 423, 497, 505, 561, 569, 609, 617, 653, 661, 686, 958, 966, 991, 999, 1034, 1042, 1067, 1075, 1636, 1644, 1675, 1683, 1725, 1733, 1822, 1830, 2099, 2236, 2373)), (4379920, 184, 'a2ea713a1ea6dff17c302754676189259a46b359e23602cd19e35192c68a3d72', (9, 37, 80, 95, 130)), (6605840, 222, '65ec6b1031b67b2e7d36675c94636e516b31abceb7776108e8a3bb47e9bd514c', (16, 28, 67, 82, 184, 190)), (4912864, 285, '66943cbeebff5d5e80972215d73af397e679a82fa06b0ea3499c6bf285355e10', (9, 32, 74, 80, 103, 114, 154, 163, 169, 185, 215, 220))), 'engine.dll': ((1522864, 80, 'bacd671052204e2333afc435e4aa3648df37f697b3d8012ebcd046ac7dd8e229', (12, 43, 62)), (1518848, 406, '8bb80fd106b9468449d507b079342683a44e6bf5325dddf7ab45bcf88c8945b2', (81, 87, 220, 225, 242, 247, 263, 275, 280, 315, 320, 343, 348, 359)), (1281776, 479, '23372891db0fa05b4b710ca1ea317ffaeb6e4e97bd86ce4dba73d855e7f34e8f', (19, 25, 335, 341)), (1000848, 27, '4a1a430415405799a87628f6bf0094f2062fd9914bad3abee07461e53ad435ad', ()), (996288, 96, '4f8ad6fe7fe9ab02e7207b46788d5f9fdeeebd38ce8d9a48d480b86e1c11c38f', (76,)))}

def heroes_model_payload(remote,server,key,path,api,guards):
    if path not in dict(HERO_MODELS).values():raise ValueError('模型不在已验证的 HERO 资源列表')
    model=remote+0x810;result=remote+0x800
    def body(_):
        code=bytearray();skips=[]
        def fail_if(op):
            code.extend(op+b'\0\0\0\0');skips.append(len(code)-4)
        # PrecacheModel is cdecl, while the engine/model and entity calls are thiscall.
        code.extend(b'\x68'+struct.pack('<I',model)+b'\xb8'+struct.pack('<I',server+0x5db440)+b'\xff\xd0\x83\xc4\x04')
        code.extend(b'\xa3'+struct.pack('<I',result)+b'\x85\xc0');fail_if(b'\x0f\x8e')
        code.extend(heroes_call(api['model_this'],api['lookup'],model))
        code.extend(b'\x3b\x05'+struct.pack('<I',result));fail_if(b'\x0f\x85')
        code.extend(b'\x50\xb9'+struct.pack('<I',api['model_this'])+b'\xb8'+struct.pack('<I',api['get_model'])+b'\xff\xd0\x85\xc0')
        fail_if(b'\x0f\x84')
        code.extend(heroes_call(key.address,server+0x51e370,model))
        code.extend(b'\x0f\xbf\x05'+struct.pack('<I',key.address+0x86))
        code.extend(b'\x3b\x05'+struct.pack('<I',result));fail_if(b'\x0f\x85')
        code.extend(b'\xc7\x05'+struct.pack('<II',result+4,1))
        for at in skips:struct.pack_into('<i',code,at,len(code)-at-4)
        return bytes(code)
    return player_action_stub(remote,guards,body,code_size=0x800)+bytes(16)+path.encode('ascii')+b'\0'


class HeroesControls:
    """Own only Heroes requests and the two temporary temple cvars."""
    def __init__(self,backend,emit):
        self.b=backend;self.emit=emit;self.pending=None;self.saved=None;self.temple_job=None
        self.protected=False;self.next_sample=0.;self.restore_error=''
        self.auto=False;self.seconds=3.;self.due=None;self.no_wait=False;self.active_context=None
        self.upgrades={};self.next_upgrade=0.;self.upgrade_rows=None;self.upgrade_error=''
        self.model_jobs={};self.next_model=0.;self.model_watch=False;self.next_model_sample=0.
    def select_models(self,path,keys,players):
        if path not in dict(HERO_MODELS).values():raise ValueError('请选择列表中的 HERO 模型')
        self.b.heroes_model_api(force=True)
        present={p.key for p in players if p.team in (2,3) and not is_tv_player(p)}
        keys=set(keys)&present
        if not keys:raise NotReady('请先勾选要切换模型的玩家')
        # Each player can have a different choice. A new choice replaces only
        # that player's queued request; completed changes are not a lock.
        for key in keys:self.model_jobs[key]=dict(path=path,retries=0)
        self.active_context=(self.b.epoch,self.b.context)
        self.emit('log',text=f'模型切换已排队：{len(keys)} 人；死亡玩家复活后应用')
    def advance_models(self,players):
        if not self.model_jobs or self.pending or time.monotonic()<self.next_model:return
        b=self.b
        if b.player_queue and b.player_queue.pending:return
        self.next_model=time.monotonic()+.15
        present={p.key:p for p in players if p.team in (2,3) and not is_tv_player(p)}
        for key in list(self.model_jobs):
            if key not in present:self.model_jobs.pop(key,None)
        for key,job in sorted(self.model_jobs.items(),key=lambda row:row[0].index):
            if not present[key].alive:continue
            try:
                sample=b.heroes_state()
                if sample['ended']:return
                api=b.heroes_model_api();guards=b.heroes_model_guards(sample,api,key)
                b.submit_player_native(lambda remote:heroes_model_payload(remote,b.server,key,job['path'],api,guards))
                self.pending=dict(action='model',key=key,model_job=job,epoch=b.epoch,context=b.context)
                return
            except PlayerUnavailable:continue
            except Exception as ex:
                reason=str(ex)
                if job.get('reason')!=reason:self.emit('error',text=f'模型切换 #{key.index} 等待：'+reason);job['reason']=reason
                return
    def sample_models(self,players):
        if not self.model_watch or time.monotonic()<self.next_model_sample:return
        self.next_model_sample=time.monotonic()+1.
        rows=[]
        try:self.b.heroes_model_api()
        except Exception as ex:self.emit('heroes_models',rows=[],reason=str(ex));return
        for p in players:
            if p.team not in (2,3) or is_tv_player(p):continue
            try:index,path=self.b.heroes_model_current(p.key)
            except (NotReady,OSError):path='';index=0
            rows.append(dict(key=p.key,path=path,index=index,alive=p.alive,pending=p.key in self.model_jobs))
        self.emit('heroes_models',rows=rows,reason='')

    def flags(self):
        self.emit('flags',heroes_auto=self.auto,heroes_no_wait=self.no_wait)
    def configure_auto(self,enabled,seconds):
        if enabled:
            seconds=bounded_float(seconds,0,3600,'怪物死亡倒计时')
            sample=self.b.heroes_state(verify=True)
            if sample['ended']:raise NotReady('本局已结束')
            self.seconds=max(.1,seconds);self.active_context=(self.b.epoch,self.b.context)
        self.auto=bool(enabled);self.due=None;self.flags()
        self.emit('log',text='怪物自动死亡：'+('开启，倒计时 '+str(seconds)+' 秒循环执行' if enabled else '关闭'))
    def configure_wait(self,enabled):
        if enabled:
            self.b.heroes_state(verify=True);self.active_context=(self.b.epoch,self.b.context)
        self.no_wait=bool(enabled);self.flags()
    def upgrade_all(self,field,level,players):
        if field not in ('atk','hp'):raise ValueError('未知强化类型')
        table=self.b.heroes_enchants(force=True);level=bounded_int(level,0,20,'强化等级')
        if level not in table['rows']:raise NotReady('当前对局没有该强化等级')
        keys={p.key for p in players if p.team in (2,3) and not is_tv_player(p)}
        if not keys:raise NotReady('当前没有参战玩家')
        self.upgrades[field]=dict(level=level,keys=keys,done=0,failed=0)
        self.active_context=(self.b.epoch,self.b.context)
        self.emit('log',text=f'全体玩家强化已排队：{field} 等级 {level}，共 {len(keys)} 人；死亡玩家复活后补发')
    def advance_upgrades(self,players):
        if not self.upgrades or self.pending or time.monotonic()<self.next_upgrade:return
        b=self.b
        if b.player_queue and b.player_queue.pending:return
        self.next_upgrade=time.monotonic()+.1
        present={p.key:p for p in players if p.team in (2,3) and not is_tv_player(p)}
        for field,job in list(self.upgrades.items()):
            job['keys'].intersection_update(present)
            for key in sorted(job['keys'],key=lambda k:k.index):
                player=present[key]
                if not player.alive or player.team not in (2,3):continue
                try:
                    sample=b.heroes_state()
                    if sample['ended']:return
                    table=b.heroes_enchants(force=True);row=table['rows'][job['level']]
                    actual=b.validate(key)
                    if actual.team not in (2,3) or is_tv_player(actual):job['keys'].discard(key);continue
                    if struct.unpack('<h',b.mem.read(key.address+0x86,2))[0]<=0:continue
                    guards=b.heroes_upgrade_guards(sample,table,key,row)
                    b.submit_player_native(lambda remote:heroes_upgrade_payload(remote,b.server,key,field,job['level'],guards))
                    self.pending=dict(action='upgrade',field=field,key=key,job=job,row=row,epoch=b.epoch,context=b.context)
                    return
                except PlayerUnavailable:continue
                except NotReady as ex:
                    # A native table/phase read can be transiently unstable
                    # during spawn or round transition. Keep this player in
                    # the batch and retry on the next game frame.
                    reason=str(ex)
                    if job.get('wait_reason')!=reason:
                        job['wait_reason']=reason;self.emit('log',text='全体强化等待恢复：'+reason)
                    return
                except Exception as ex:
                    job['keys'].discard(key);job['failed']+=1
                    self.emit('error',text=f'全体强化 #{key.index} 未执行：{ex}')
            if not job['keys']:
                self.upgrades.pop(field,None)
                self.emit('log',text=f'全体强化 {field} 完成：已确认 {job["done"]} 人，失败 {job["failed"]} 人')
    def automate(self,sample):
        if sample['ended']:
            self.auto=False;self.no_wait=False;self.due=None;self.upgrades.clear();self.model_jobs.clear();self.flags();return
        now=time.monotonic()
        if not self.auto or sample['phase']!=3:self.due=None
        elif self.due is None:self.due=now+self.seconds
        if self.pending or self.b.player_queue and self.b.player_queue.pending:return
        if self.no_wait and sample['phase'] in (2,4):
            offset=0x18 if sample['phase']==2 else 0x20
            if self.b.mem.i32(sample['fsm']+offset)!=0:self.native('no_wait',quiet=True)
        elif self.auto and sample['phase']==3 and now>=self.due:
            self.native('kill',quiet=True);self.due=None

    def native(self,action,target=None,quiet=False):
        if self.pending:raise NotReady('上一项洛奇操作正在等游戏处理')
        b=self.b;sample=b.heroes_state(table=action=='jump',verify=not quiet)
        if sample['ended']:raise NotReady('本局已结束，请等待下一局')
        if sample['phase']==1:raise NotReady('等待洛奇对局开始')
        if action=='finish' and sample['phase']==4:raise NotReady('当前波已经进入结束阶段')
        if action=='jump':
            target=bounded_int(target,1,len(sample['waves']),'目标波次')
            if target not in sample['waves']:raise NotReady('地图没有加载该波次')
        if b.player_queue and b.player_queue.pending:raise NotReady('上一项游戏操作尚未结束')
        guards=b.heroes_guards(sample)
        if action=='jump':
            guards.extend(((b.server+0xc23360,sample['head']),(b.server+0xc23364,len(sample['waves']))))
            node=sample['waves'][target];guards.extend(((node+0x10,target),(node+0x14,target)))
        b.submit_player_native(lambda remote:heroes_native_payload(remote,b.server,sample,guards,action,target))
        self.pending=dict(action=action,target=target,sample=sample,epoch=b.epoch,context=b.context,quiet=quiet)
        if not quiet:self.emit('log',text='洛奇操作已排入游戏主线程，等待执行结果')
    def protect(self,enabled):
        if self.temple_job:raise NotReady('神殿保护切换尚未核对完成')
        b=self.b
        if enabled:
            b.heroes_state(verify=True)
            values=b.heroes_damage_values()
            if self.saved is None:self.saved=dict(identity=(b.mem.pid,b.server),values=values,context=b.context,epoch=b.epoch)
            self.temple_job=dict(enabled=True,deadline=time.monotonic()+8.,sent=False)
        else:
            self.protected=False
            if self.saved:self.temple_job=dict(enabled=False,deadline=time.monotonic()+8.,sent=False)
        self.advance_temple()
    def advance_temple(self):
        job=self.temple_job;b=self.b
        if not job:return
        if not b.mem or self.saved['identity'][0]!=b.mem.pid:
            # A different process/module cannot own the old cvar objects.
            self.saved=None;self.temple_job=None;self.protected=False;return
        enabled=job['enabled'];desired=['0','0'] if enabled else self.saved['values']
        try:
            if b.server!=self.saved['identity'][1]:raise NotReady('等待原服务器模块恢复连接后还原神殿参数')
            if enabled and (self.saved['epoch']!=b.epoch or self.saved['context']!=b.current_context()):
                self.protected=False;job.update(enabled=False,sent=False,deadline=time.monotonic()+8.);return
            values=b.heroes_damage_values()
            # A restore must be queued even if the old value is still visible:
            # a preceding enable command may not have reached the game yet.
            if not job['sent']:
                b.send('; '.join(name+' '+value for name,value in zip(HEROES_DAMAGE,desired)));job['sent']=True
                return
            if all(float(a)==float(z) for a,z in zip(values,desired)):
                self.protected=enabled;self.temple_job=None;self.restore_error=''
                if not enabled:self.saved=None
                self.emit('log',text='神殿保护已开启（普通怪与 Boss 伤害均已读回为 0）' if enabled else '神殿保护已关闭，两项伤害参数已恢复原值')
                return
            if time.monotonic()>job['deadline']:raise NotReady('两项神殿伤害参数未在时限内达到目标值')
        except Exception as ex:
            message='神殿保护：'+str(ex)
            if message!=self.restore_error:self.emit('error',text=message);self.restore_error=message
            self.protected=False
            # A failed enable can have changed one cvar. Roll back BOTH.
            job.update(enabled=False,sent=False,deadline=time.monotonic()+8.)
    def restore_temple(self):
        self.protected=False
        if self.saved:
            self.temple_job=dict(enabled=False,deadline=time.monotonic()+8.,sent=False)
            self.advance_temple()
    def reset(self):
        self.pending=None
        self.auto=False;self.no_wait=False;self.due=None;self.active_context=None;self.upgrades.clear();self.model_jobs.clear();self.upgrade_rows=None;self.flags()
        self.restore_temple()
    def step(self,players=()):
        b=self.b
        if self.active_context is not None and self.active_context!=(b.epoch,b.current_context()):
            self.auto=False;self.no_wait=False;self.due=None;self.upgrades.clear();self.model_jobs.clear();self.active_context=None;self.flags()
        if self.pending:
            job=self.pending
            try:
                if job['epoch']!=b.epoch or job['context']!=b.current_context():raise NotReady('对局已变化，洛奇操作取消')
                if b.player_queue and b.player_queue.poll():
                    self.pending=None;now=b.heroes_state();action=job['action']
                    if action=='model':
                        key=job['key'];index,path=b.heroes_model_current(key)
                        if b.mem.u32(b.player_queue.request+0x804)!=1 or index<=0 or path!=job['model_job']['path']:
                            raise NotReady('模型未达到目标：预缓存失败或原生角色规则覆盖了选择')
                        if self.model_jobs.get(key) is job['model_job']:self.model_jobs.pop(key,None)
                        self.next_model_sample=0.
                        self.emit('log',text=f'模型已读回确认：#{key.index} → '+Path(path).stem)
                    if action=='upgrade':
                        key=job['key'];b.validate(key,False);row=job['row'];field=job['field']
                        offset=0x26b4 if field=='atk' else 0x26b5
                        value=struct.unpack('<f',b.mem.read(key.address+0x1be4,4))[0] if field=='atk' else b.mem.i32(key.address+0xf0)
                        if b.mem.read(key.address+offset,1)[0]!=row['level'] or not math.isclose(value,row[field],rel_tol=1e-6):
                            raise NotReady('强化调用已执行，但等级/实际属性未达到目标')
                        job['job']['keys'].discard(key);job['job']['done']+=1
                    if action=='no_wait' and now['fsm']==job['sample']['fsm'] and now['phase']==job['sample']['phase']:
                        offset=0x18 if now['phase']==2 else 0x20
                        if b.mem.i32(now['fsm']+offset)!=0:raise NotReady('等待时间未归零')
                    if action=='jump' and (now['wave']!=job['target'] or now['phase']!=3 or now['ended']):
                        raise NotReady('跳波调用已执行，但未读回目标攻击阶段')
                    if action=='finish' and not (now['ended'] or now['wave']>job['sample']['wave'] or now['phase']==4):
                        raise NotReady('结束调用已执行，但尚未观察到本波结束')
                    text={'kill':'原生怪物死亡流程已执行；后续怪物仍按本波配置出生',
                          'finish':'本波已进入结束/结算流程',
                          'jump':'已读回第 '+str(job.get('target'))+' 波攻击阶段',
                          'no_wait':'等待时间已归零','upgrade':'强化属性已读回','model':'模型切换已确认'}[action]
                    if action not in ('upgrade','model') and not job.get('quiet'):self.emit('log',text=text)
            except Exception as ex:
                self.pending=None
                if job['action']=='model':
                    item=job['model_job'];item['retries']+=1
                    try:dead=not b.validate(job['key'],False).alive
                    except (NotReady,OSError):dead=False
                    if not dead and item['retries']>=2 and self.model_jobs.get(job['key']) is item:self.model_jobs.pop(job['key'],None)
                if job['action']=='upgrade':
                    retry=False
                    if job['epoch']==b.epoch and job['context']==b.context:
                        try:
                            player=b.validate(job['key'],False)
                            retries=job['job'].setdefault('retries',{})
                            retries[job['key']]=retries.get(job['key'],0)+1
                            retry=not player.alive or retries[job['key']]<=3
                        except (NotReady,OSError):pass
                    if not retry:job['job']['keys'].discard(job['key']);job['job']['failed']+=1
                elif job.get('quiet'):
                    # A state transition between sampling and the game frame is
                    # retried on the next sample, without accumulating requests.
                    if job['epoch']!=b.epoch:self.auto=False;self.no_wait=False;self.flags()
                self.emit('error',text='洛奇操作未确认：'+str(ex))
        self.sample_models(players)
        self.advance_models(players)
        self.advance_upgrades(players)
        if time.monotonic()<self.next_sample:return
        self.next_sample=time.monotonic()+.4
        self.advance_temple()
        try:
            sample=b.heroes_state()
            if self.protected:
                if self.saved['epoch']!=b.epoch or self.saved['context']!=b.context:self.reset()
                elif any(float(v)!=0 for v in b.heroes_damage_values()):
                    self.emit('error',text='神殿伤害参数被外部更改，保护未保持，正在恢复原值');self.reset()
            phase={1:'等待开始',2:'准备',3:'攻击',4:'结束'}[sample['phase']]
            text=f'第 {sample["wave"]} 波 · '+('本局结束' if sample['ended'] else phase)+f' · 神殿生命 {sample["health"]} · 本波剩余 {sample["remaining"]}'
            self.automate(sample)
            if self.auto:text+=' · 自动清怪 '+(f'{max(0.,self.due-time.monotonic()):.1f} 秒' if self.due else '等待攻击/执行结果')
            if self.upgrades:text+=' · 等待强化 '+str(sum(len(j['keys']) for j in self.upgrades.values()))+' 人次'
            self.state_error=''
            self.emit('heroes_state',text=text,protected=self.protected)
            try:
                table=b.heroes_enchants();rows=[(k,r['atk'],r['hp']) for k,r in sorted(table['rows'].items())]
                if rows!=self.upgrade_rows:self.upgrade_rows=rows;self.emit('heroes_levels',rows=rows)
                self.upgrade_error=''
            except Exception as ex:
                reason=str(ex)
                self.upgrade_rows=None
                if reason!=self.upgrade_error:self.emit('heroes_levels',rows=[],reason=reason);self.upgrade_error=reason
        except Exception as ex:
            # Same-session reads can fail during a native phase transition.
            # Retain requested automation and unfinished upgrades; every retry
            # validates mode, context, entity identity and native guards again.
            self.due=None
            if self.protected:self.restore_temple()
            reason=str(ex)
            self.emit('heroes_state',text='洛奇功能暂不可用：'+reason,protected=False)
            if reason!=getattr(self,'state_error',''):
                self.emit('log',text='洛奇功能不可用原因：'+reason)
            self.state_error=reason
    def close(self):
        self.reset()
        # Queue completion alone is not success: allow a bounded read-back
        # window before the existing connection closes.
        until=time.monotonic()+1.5
        while self.temple_job and time.monotonic()<until:
            self.advance_temple()
            if self.temple_job:time.sleep(.05)
        if self.temple_job:self.emit('error',text='关闭时未确认神殿参数恢复；原值：'+repr(self.saved['values']))


COMBAT_DAMAGE_MANIFEST=(6511750, 2306, '2360b463db48611c68a3246cd122e60e9f86aea93e2ce70227ea9959180647c0', (9, 91, 131, 168, 210, 277, 357, 433, 440, 470, 498, 522, 578, 586, 593, 619, 647, 667, 682, 737, 760, 769, 775, 809, 830, 854, 882, 927, 943, 957, 969, 1008, 1071, 1145, 1150, 1230, 1246, 1286, 1337, 1377, 1499, 1507, 1725, 1878, 1934, 1975, 2216, 2235))
# The common monster damage entry runs after weapon/hitgroup multipliers.
COMBAT_ENTRY=0x635c80
COMBAT_PREFIX=bytes.fromhex('558bec83e4f8')
COMBAT_TARGET_CHECKS=((0x630164,bytes.fromhex('8b8ee00600008bc1c1e80fa8010f8580010000c1e907f6c1010f8574010000')),
    (0x633f38,bytes.fromhex('8b8ee00600008bc1c1e80fa801756ac1e907f6c1017562')),
    (0x638533,bytes.fromhex('8b8ee00600008bc1c1e80fa80175dac1e907f6c10175d2')))

def heroes_fixed_damage(value):
    number=bounded_int(value,1,2000000000,'自定义伤害')
    return struct.unpack('<f',struct.pack('<f',number))[0]

def combat_damage_code(remote,server,engine):
    """Reentrant thiscall wrapper; the caller's const damage-info stays untouched."""
    data=remote+0x800;trampoline=remote+0x600;code=bytearray();branches=[]
    def emit(value):code.extend(bytes.fromhex(value))
    def imm(value):code.extend(struct.pack('<I',value))
    def skip(op):
        emit(op);branches.append(len(code));code.extend(bytes(4))
    emit('558bec9c60833d');imm(data+4);emit('01');skip('0f85')
    emit('a1');imm(server+0xc5f590);emit('3b05');imm(data+12);skip('0f85')
    emit('85c0');skip('0f84')
    emit('8138');imm(server+0x8f3134);skip('0f85')
    emit('833d');imm(engine+9249476);emit('06');skip('0f85')
    emit('a1');imm(engine+0x8d21a0);emit('3b05');imm(data+16);skip('0f85')
    emit('83b9f400000000');skip('0f8e')
    emit('8b75088b463085c0');skip('0f8e')
    emit('3d0000807f');skip('0f83') # Ignore zero/healing/non-finite events.
    emit('8b46280fb7d083fa01');skip('0f82')
    emit('83fa40');skip('0f87')
    emit('c1e20481c2');imm(server+0xa5fa44)
    emit('c1e810394204');skip('0f85')
    emit('8b1285d2');skip('0f84')
    emit('813a');imm(server+0x8b7100);skip('0f85')
    emit('0fb6820102000083e80283f801');skip('0f87')
    # A raw, read-only shadow of CTakeDamageInfo (0x84 bytes). Its embedded
    # string is borrowed for this call only and must not be destructed.
    emit('81ec8400000089e7b921000000fcf3a5a1');imm(data+8)
    emit('894424308b4df489e050b8');imm(trampoline);emit('ffd08945f8')
    emit('8d65dc619dc9c20400')
    passthrough=len(code);emit('619dc9e9');imm((trampoline-(remote+len(code)+4))&0xffffffff)
    for at in branches:struct.pack_into('<i',code,at,passthrough-at-4)
    if len(code)>=0x600:raise ValueError('伤害回调超过预留空间')
    code.extend(bytes(0x600-len(code)));code+=COMBAT_PREFIX+b'\xe9'+struct.pack('<I',(server+COMBAT_ENTRY+6-(trampoline+11))&0xffffffff)
    return bytes(code)

class CombatDamageHook:
    """Install once on GameFrame. Disabled pages remain valid until game exit."""
    def __init__(self,backend):
        self.b=backend;self.m=backend.mem;self.k=self.m.k;self.handle=None;self.remote=0;self.pending=False;self.installed=False;self.protection=None
        self.target=backend.server+COMBAT_ENTRY;self.desired=None;self.enabled=False;self.identity=(backend.epoch,backend.context)
        for name,ret,args in (
            ('VirtualAllocEx',C.c_void_p,[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,W.DWORD]),
            ('VirtualProtectEx',W.BOOL,[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,C.POINTER(W.DWORD)]),
            ('FlushInstructionCache',W.BOOL,[W.HANDLE,C.c_void_p,C.c_size_t])):
            fn=getattr(self.k,name);fn.restype=ret;fn.argtypes=args
        self.handle=self.k.OpenProcess(0x0438,False,self.m.pid)
        if not self.handle:raise C.WinError(C.get_last_error())
        try:
            entry=self.m.read(self.target,6)
            if entry!=COMBAT_PREFIX:
                self.remote=self.existing(backend)
                if not self.remote:raise NotReady('怪物受击入口由其他修改占用')
                if self.m.u32(self.remote+0x804):raise NotReady('另一房主工具正在使用自定义伤害')
                self.installed=True
            else:
                self.remote=self.k.VirtualAllocEx(self.handle,None,4096,0x3000,0x40)
                if not self.remote or self.remote>=0xffff0000:raise OSError('无法分配伤害回调')
                self.m.write(self.remote,combat_damage_code(self.remote,backend.server,backend.engine))
                self.m.write(self.remote+0x800,b'CDM1'+bytes(16)+struct.pack('<III',backend.server,backend.engine,self.target))
                if not self.k.FlushInstructionCache(self.handle,self.remote,0x800):raise C.WinError(C.get_last_error())
        except Exception:
            if self.handle:self.k.CloseHandle(self.handle);self.handle=None
            raise
    @staticmethod
    def existing(b):
        entry=b.mem.read(b.server+COMBAT_ENTRY,6)
        if entry[0]!=0xe9 or entry[5]!=0x90:return 0
        remote=(b.server+COMBAT_ENTRY+5+struct.unpack_from('<i',entry,1)[0])&0xffffffff
        if not 0x10000<=remote<0xfffe0000:return 0
        try:
            if b.mem.read(remote+0x800,4)!=b'CDM1':return 0
            if b.mem.read(remote+0x814,12)!=struct.pack('<III',b.server,b.engine,b.server+COMBAT_ENTRY):return 0
            code=combat_damage_code(remote,b.server,b.engine)
            return remote if b.mem.read(remote,len(code))==code else 0
        except (OSError,NotReady):return 0
    def configure(self,value):
        self.desired=value
        if value is None:self.disable();return
        self.identity=(self.b.epoch,self.b.context)
    def disable(self):
        self.desired=None
        if self.remote:self.m.write(self.remote+0x804,bytes(4))
        self.enabled=False
    def restore_protection(self):
        if self.protection is None:return
        old=W.DWORD()
        if not self.k.VirtualProtectEx(self.handle,self.target,6,self.protection,C.byref(old)):raise C.WinError(C.get_last_error())
        self.protection=None
    def step(self):
        b=self.b
        if self.pending:
            q=b.player_queue
            if q is None:raise NotReady('伤害安装队列已取消')
            try:
                if not q.poll():return False
            except Exception:
                if not q.pending:self.pending=False;self.restore_protection()
                raise
            self.pending=False
            self.restore_protection()
            if not self.k.FlushInstructionCache(self.handle,self.target,6):raise C.WinError(C.get_last_error())
            if self.m.read(self.target,6)!=self.patch:raise NotReady('伤害回调未由游戏帧安装')
            self.installed=True
        if self.desired is None:return False
        if self.identity!=(b.epoch,b.current_context()):self.disable();return False
        sample=b.heroes_state()
        if sample['ended']:self.disable();return False
        if not self.installed:
            if b.player_queue and b.player_queue.pending:return False
            expected=self.m.read(self.target,8)
            if expected[:6]!=COMBAT_PREFIX:raise NotReady('怪物受击入口已变化')
            self.patch=b'\xe9'+struct.pack('<I',(self.remote-self.target-5)&0xffffffff)+b'\x90'
            guards=b.heroes_guards(sample)+[(self.target,struct.unpack_from('<I',expected)[0]),(self.target+4,struct.unpack_from('<I',expected,4)[0])]
            body=b'\xc7\x05'+struct.pack('<II',self.target,struct.unpack_from('<I',self.patch)[0])+b'\x66\xc7\x05'+struct.pack('<IH',self.target+4,struct.unpack_from('<H',self.patch,4)[0])
            old=W.DWORD()
            if not self.k.VirtualProtectEx(self.handle,self.target,6,0x40,C.byref(old)):raise C.WinError(C.get_last_error())
            self.protection=old.value
            try:b.submit_player_native(lambda remote:player_action_stub(remote,guards,lambda _:body));self.pending=True
            except Exception:self.restore_protection();raise
            return False
        if self.enabled and self.m.read(self.remote+0x808,4)==struct.pack('<f',self.desired):return True
        self.m.write(self.remote+0x804,bytes(4))
        self.m.write(self.remote+0x808,struct.pack('<fII',self.desired,sample['rules'],self.m.u32(b.engine+0x8d21a0)))
        self.m.write(self.remote+0x804,struct.pack('<I',1))
        self.enabled=True;return True
    def close(self):
        try:
            self.disable()
            # A queued patch must finish/cancel before restoring page protection.
            try:
                if self.pending and self.b.player_queue:
                    until=time.monotonic()+2.2
                    while time.monotonic()<until:
                        if self.b.player_queue.poll():self.pending=False;break
                        time.sleep(.02)
            finally:
                if self.pending and self.b.player_queue and not self.b.player_queue.pending:self.pending=False
                if not self.pending:self.restore_protection()
        finally:
            if self.handle:self.k.CloseHandle(self.handle);self.handle=None
        # Never free a trampoline while a native call can still return through it.

class HeroesCombatControls:
    def __init__(self,b,emit):
        self.b=b;self.emit=emit;self.hook=None;self.no_attack=False;self.saved={};self.next_sample=0.;self.identity=None;self.errors={}
    def flags(self):
        self.emit('flags',heroes_custom_damage=bool(self.hook and self.hook.enabled),heroes_no_attack=self.no_attack)
    def damage(self,enabled,value):
        if enabled:
            value=heroes_fixed_damage(value);self.b.verify_combat_damage()
            if self.hook is None:self.hook=CombatDamageHook(self.b)
            self.hook.configure(value);self.identity=(self.b.epoch,self.b.context)
            self.emit('log',text=f'自定义伤害已提交，实际单次伤害值 {value:.0f}；等待游戏帧安装')
        elif self.hook:
            self.hook.disable();self.emit('log',text='自定义伤害已关闭，恢复原生伤害')
        self.flags()
    def protect(self,enabled,players):
        if enabled:
            self.b.verify_combat_targets();self.no_attack=True;self.identity=(self.b.epoch,self.b.context);self.next_sample=0.
            try:self.apply_targets(players)
            except Exception:
                self.no_attack=False
                try:self.restore_targets()
                finally:self.flags()
                raise
        else:
            self.no_attack=False;self.restore_targets()
        self.flags();self.emit('log',text='怪物不攻击玩家：'+('已开启' if enabled else '已关闭'))
    def apply_targets(self,players):
        b=self.b
        if b.current_context()!=b.context:raise NotReady('对局已变化')
        valid={p.key for p in players};self.saved={k:v for k,v in self.saved.items() if k in valid}
        eligible={p.key for p in players if can_set_player_values(p)}
        self.restore_targets(set(self.saved)-eligible)
        for key in eligible:
            p=b.validate(key)
            if not can_set_player_values(p):continue
            b.network_target(key.address,key.index)
            at=key.address+0x6e0;before=b.mem.read(at,1)[0]
            if key not in self.saved:self.saved[key]=not bool(before&0x80)
            if not before&0x80:
                # One byte, preserving all unrelated bits and the upper bytes.
                self.saved[key]=True;b.mem.write(at,bytes([before|0x80]));b.dirty(key.address,key.index)
    def restore_targets(self,keys=None):
        b=self.b;errors=[]
        for key in list(self.saved) if keys is None else list(keys):
            if key not in self.saved:continue
            if key.epoch!=b.epoch or key.map_name!=b.map_name:self.saved.pop(key,None);continue
            try:
                b.validate(key,False)
                if self.saved[key]:
                    at=key.address+0x6e0;before=b.mem.read(at,1)[0]
                    if before&0x80:b.mem.write(at,bytes([before&~0x80]));b.dirty(key.address,key.index)
                self.saved.pop(key,None)
            except PlayerUnavailable:self.saved.pop(key,None)
            except Exception as ex:errors.append(str(ex))
        if errors:raise NotReady('怪物目标标志尚待恢复：'+errors[0])
    def step(self,players):
        try:
            if self.identity and self.identity!=(self.b.epoch,self.b.current_context()):self.reset()
        except Exception:
            self.reset();return
        due=time.monotonic()>=self.next_sample
        if due:self.next_sample=time.monotonic()+.4
        try:
            if self.hook and (self.hook.pending or (due and self.hook.desired is not None)):
                was=self.hook.enabled
                if self.hook.step() and not was:
                    self.emit('log',text=f'所有玩家自定义伤害已启用：{self.hook.desired:.0f}')
                    self.flags()
            self.errors.pop('damage',None)
        except Exception as ex:
            try:self.hook.disable()
            except Exception:pass
            self.report_error('damage',ex)
        if not due:return
        try:
            if self.no_attack:
                self.b.heroes_state();self.apply_targets(players)
            elif self.saved:self.restore_targets()
            self.errors.pop('target',None)
        except Exception as ex:
            self.no_attack=False
            self.report_error('target',ex)
    def report_error(self,feature,ex):
        reason=str(ex)
        if reason!=self.errors.get(feature):self.emit('error',text=('自定义伤害：' if feature=='damage' else '怪物停攻：')+reason)
        self.errors[feature]=reason;self.flags()
    def reset(self):
        self.no_attack=False;self.identity=None
        if self.hook:
            try:self.hook.disable()
            except Exception as ex:self.emit('error',text='伤害回调关闭：'+str(ex))
        try:self.restore_targets()
        except Exception as ex:self.emit('error',text=str(ex))
        self.flags()
    def close(self):
        self.reset()
        if self.hook:
            try:self.hook.close()
            except Exception as ex:self.emit('error',text='伤害回调清理：'+str(ex))
            self.hook=None



class Backend:
    def __init__(self):
        self.mem=None;self.queue=None;self.mods={};self.server=0;self.epoch=0;self.map_name='';self.local_index=0;self.context=None;self.mutation_pending=None
        self.player_queue=None;self.buy_time_saved=None
        self.module_loader=modules;self.next_modules=0.;self.core_verified=False;self.server_reason='未连接';self.capabilities={}
        self.catalog={row['name'].casefold():row for row in DATA['catalog']}
    def connect(self,preferred=None,cancelled=None):
        self.close()
        pid,self.mods=discover_client(self.module_loader,preferred,cancelled,
            probe=lambda item:self.probe_client(item,cancelled))
        self.client=self.mods['client.dll'][0];self.engine=self.mods['engine.dll'][0]
        self.game=game_root(self.mods['client.dll'][2]);self.epoch+=1
        try:
            try:self.mem=WinMemory(pid)
            except OSError as ex:
                info=process_info(pid);elevate=info.get('elevated') is True and not is_admin()
                tip='；点击“管理员连接”重试' if elevate else ''
                raise ConnectionProblem(str(ex)+tip,'memory_open_failed',elevate) from ex
            self.verify_core();self.refresh_server(force=True);self.refresh_capabilities()
            if cancelled and cancelled():raise ConnectionProblem('连接请求已取消','cancelled')
        except Exception:self.close();raise
        return pid
    def probe_client(self,item,cancelled=None):
        if cancelled and cancelled():raise ConnectionProblem('连接请求已取消','cancelled')
        probe=Backend();probe.module_loader=self.module_loader
        try:
            pid,probe.mods=item
            probe.client=probe.mods['client.dll'][0];probe.engine=probe.mods['engine.dll'][0]
            probe.mem=WinMemory(pid);probe.verify_core()
            if not probe.mem.alive():return None
            # Read both fields even in the lobby: an unreadable live handle
            # cannot outrank a healthy client merely because its PID exists.
            signon=probe.mem.i32(probe.engine+9249476)
            level=probe.mem.string(probe.engine+9249588,128)
            if signon!=6 or not level:return 0
            try:probe.current_context()
            except NotReady:return 0
            return 1
        except (NotReady,OSError,CompatibilityError):return None
        finally:probe.close()
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
            if current.get(name)!=self.mods.get(name):raise ConnectionProblem('客户端模块已变化，正在重新发现','modules_changed')
        self.verify_core()
        self.mods=current;self.server=0;self.server_reason='当前未加载本地服务器模块'
        if 'server.dll' in current:
            try:self.bind_server()
            except Exception as ex:self.server_reason=str(ex)
    def bind_server(self):
        image=self.verify_file('server.dll');base=self.mods['server.dll'][0]
        for rva,signature in SERVER_SIGNATURES.items():
            expected=signature.replace(struct.pack('<I',image.image_base+0xa5fa44),
                                       struct.pack('<I',base+0xa5fa44))
            if self.mem.read(base+rva,len(expected))!=expected:
                raise CompatibilityError(f'server.dll 运行中关键指令变化：{rva:#x}')
        self.server=base;self.server_reason=''
    def local_connection(self):
        try:return native_loopback(self)
        except Exception as ex:raise NotReady(str(ex)) from ex
    def require_local(self):
        if not self.server:raise NotReady(self.server_reason)
        if not self.local_connection():raise NotReady('当前连接未确认为本地房主')
    def check_fields(self,names):
        field_check(self.mem,self.server,[item for item in FIELDS if item[1] in names])
    def verify_heroes_paths(self):
        m=self.mem;s=self.server;delta=s-0x10000000
        for rva,size,digest,relocs in HEROES_CODE:
            data=bytearray(m.read(s+rva,size))
            for offset in relocs:struct.pack_into('<I',data,offset,(struct.unpack_from('<I',data,offset)[0]-delta)&0xffffffff)
            if hashlib.sha256(data).hexdigest()!=digest:raise NotReady(f'洛奇原生调用路径版本不符：{rva:#x}')
        # SendPropInt (server+0x367e30) stores the name at +0x30 and
        # the entity field offset at +0x48. These are NOT datamap entries.
        field_check(m,s,[(0xcb5528+0x30,'m_nCurHealth',0x488,0x18),
                         (0xcb5578+0x30,'m_nCurrentPhaseCount',0x48c,0x18),
                         (0xcb55c8+0x30,'m_nNeedMonsterCount',0x490,0x18)])
    def heroes_state(self,table=False,verify=False):
        self.require_local();m=self.mem;s=self.server
        rules=m.u32(s+0xc5f590)
        if not rules or rules!=m.u32(s+0xc5907c) or m.u32(rules)!=s+0x8f3134:
            raise NotReady('此项仅适用于本地房主的洛奇英雄传模式')
        identity=(self.epoch,s,rules)
        if verify or getattr(self,'heroes_verified',None)!=identity:
            self.verify_heroes_paths();self.heroes_verified=identity
        fsm=m.u32(rules+0x464);vt=m.u32(fsm);phase=HEROES_STATES.get(vt-s)
        if phase is None or m.u32(fsm+4)!=rules:raise NotReady('洛奇波次正在切换')
        ended=m.read(rules+0x480,1)[0]
        health,wave,remaining=struct.unpack('<3i',m.read(rules+0x488,12))
        if ended not in (0,1) or not 0<=wave<=31 or not 0<=health<=255 or not -8192<=remaining<=1000000:
            raise NotReady('洛奇模式状态尚未就绪')
        result=dict(rules=rules,fsm=fsm,vt=vt,phase=phase,ended=bool(ended),health=health,wave=wave,remaining=remaining)
        if table:
            head=m.u32(s+0xc23360);count=m.u32(s+0xc23364)
            if not head or not 1<=count<=31:raise NotReady('地图波次表未加载或超出当前网络格式')
            todo=[m.u32(head+4)];waves={};seen=set()
            while todo:
                node=todo.pop()
                if node==head:continue
                if not node or node in seen or len(seen)>=count:raise NotReady('地图波次树正在变化')
                seen.add(node);raw=m.read(node,0x30)
                left,_,right=struct.unpack_from('<3I',raw);key,value=struct.unpack_from('<2i',raw,0x10)
                if raw[0xd] or key in waves or key!=value:raise NotReady('地图波次资源未确认')
                waves[key]=node;todo.extend((left,right))
            if set(waves)!=set(range(1,count+1)) or head!=m.u32(s+0xc23360) or count!=m.u32(s+0xc23364):
                raise NotReady('地图波次资源不连续或正在加载')
            result.update(head=head,waves=waves)
        if rules!=m.u32(s+0xc5f590) or fsm!=m.u32(rules+0x464) or vt!=m.u32(fsm):raise NotReady('洛奇波次正在切换')
        return result
    def heroes_guards(self,sample):
        s=self.server;m=self.mem;rules=sample['rules'];fsm=sample['fsm']
        guards=[(s+0xc5f590,rules),(s+0xc5907c,rules),(rules,s+0x8f3134),
                (rules+0x464,fsm),(fsm,sample['vt']),(fsm+4,rules),(rules+0x48c,sample['wave']),
                (rules+0x480,m.u32(rules+0x480)),(self.engine+9249476,6),
                (self.engine+0x8d21a0,m.u32(self.engine+0x8d21a0))]
        if self.current_context()!=self.context:raise NotReady('对局正在切换')
        event=m.u32(s+0xc59050)
        if not event:raise NotReady('模式事件系统尚未就绪')
        guards.append((s+0xc59050,event));return guards
    def heroes_enchants(self,force=False):
        sample=self.heroes_state();m=self.mem;s=self.server;rules=sample['rules']
        identity=(self.epoch,s,rules)
        if force or getattr(self,'heroes_upgrade_verified',None)!=identity:
            delta=s-0x10000000
            for rva,size,digest,relocs in HEROES_UPGRADE_CODE:
                data=bytearray(m.read(s+rva,size))
                for off in relocs:struct.pack_into('<I',data,off,(struct.unpack_from('<I',data,off)[0]-delta)&0xffffffff)
                if hashlib.sha256(data).hexdigest()!=digest:raise NotReady(f'玩家强化原生路径版本不符：{rva:#x}')
            if m.u32(s+0x8f3134+0x49c)!=s+0x61da90:raise NotReady('强化表查询接口不匹配')
            self.heroes_upgrade_verified=identity
        head=m.u32(rules+0x478);count=m.u32(rules+0x47c);stamp=identity+(head,count)
        if not head or not 1<=count<=21:raise NotReady('本局强化配置表尚未加载')
        cache=getattr(self,'heroes_enchant_cache',None)
        if not force and cache and cache['stamp']==stamp and time.monotonic()<cache['expires']:return cache
        todo=[m.u32(head+4)];rows={};seen=set()
        while todo:
            node=todo.pop()
            if node==head:continue
            if not node or node in seen or len(seen)>=count:raise NotReady('强化配置树正在变化')
            seen.add(node);raw=m.read(node,0x28)
            left,_,right=struct.unpack_from('<3I',raw);key,level,atk,hp,atk_cost,hp_cost=struct.unpack_from('<iifiii',raw,0x10)
            if raw[0xd] or key!=level or key in rows or not 0<=key<=20 or not math.isfinite(atk) or not 0<atk<=10000 or not 1<=hp<=100000000:
                raise NotReady('强化配置内容未确认')
            rows[key]=dict(node=node,level=level,atk=atk,hp=hp,raw=raw[0x10:0x28]);todo.extend((left,right))
        if len(rows)!=count or head!=m.u32(rules+0x478) or count!=m.u32(rules+0x47c):raise NotReady('强化配置表正在加载')
        self.heroes_enchant_cache=dict(stamp=stamp,expires=time.monotonic()+2.,head=head,count=count,rows=rows)
        return self.heroes_enchant_cache
    def heroes_upgrade_guards(self,sample,table,key,row):
        m=self.mem;p=key.address;s=self.server;rules=sample['rules'];vt=m.u32(p)
        guards=self.heroes_guards(sample)+self.action_guards(key)
        guards.extend(((rules+0x478,table['head']),(rules+0x47c,table['count']),
                       (s+0x8f3134+0x49c,s+0x61da90),(p,vt)))
        for offset in range(0,len(row['raw']),4):guards.append((row['node']+0x10+offset,struct.unpack_from('<I',row['raw'],offset)[0]))
        # Check on the game frame as well: do not upgrade a corpse, spectator,
        # replaced slot or model that vanished after the roster sample.
        for offset in (0xf8,0x200,0x84):
            value=m.u32(p+offset)
            if offset==0xf8 and value&0xff:raise PlayerUnavailable('玩家刚刚死亡，复活后再强化')
            if offset==0x200 and (value>>8)&0xff not in (2,3):raise PlayerUnavailable('玩家刚刚离开参战阵营')
            guards.append((p+offset,value))
        if m.i32(p+0xf4)<=0:raise PlayerUnavailable('等待玩家存活后强化')
        for offset in (0x23c,0x248,0x250):
            method=m.u32(vt+offset)
            if not s<=method<s+0x750000:raise NotReady('玩家属性虚函数不属于当前服务端')
            guards.append((vt+offset,method))
        return guards
    def heroes_model_api(self,force=False):
        self.heroes_state();m=self.mem;s=self.server;e=self.engine
        identity=(self.epoch,s,e)
        if force or getattr(self,'model_verified',None)!=identity:
            for name,items in HERO_MODEL_CODE.items():
                base=s if name=='server.dll' else e;delta=base-0x10000000
                for rva,size,digest,relocs in items:
                    data=bytearray(m.read(base+rva,size))
                    for off in relocs:struct.pack_into('<I',data,off,(struct.unpack_from('<I',data,off)[0]-delta)&0xffffffff)
                    if hashlib.sha256(data).hexdigest()!=digest:raise NotReady(f'人物模型原生路径版本不符：{name} {rva:#x}')
            field_check(m,s,[(0x9bff78,'m_nModelIndex',0x86,4)])
            self.model_verified=identity
        engine_this=m.u32(s+0xc59074);model_this=m.u32(s+0xc58fdc)
        if not engine_this or not model_this:raise NotReady('模型加载接口尚未就绪')
        ev=m.u32(engine_this);mv=m.u32(model_this)
        if ev!=e+0x5edd74 or mv!=e+0x5de7fc:raise NotReady('模型引擎接口不匹配')
        for address,wanted in ((ev+0x14,e+0x173cb0),(mv+4,e+0xf4590),(mv+8,e+0xf33c0)):
            if m.u32(address)!=wanted:raise NotReady('模型接口方法发生变化')
        return dict(engine_this=engine_this,model_this=model_this,engine_vt=ev,model_vt=mv,
                    lookup=e+0xf33c0,get_model=e+0xf4590)
    def heroes_model_current(self,key):
        self.validate(key,False);m=self.mem
        # Native UTIL_SetModel assigns this pooled model-path string at +0x214.
        index=struct.unpack('<h',m.read(key.address+0x86,2))[0]
        pointer=m.u32(key.address+0x214)
        path=m.string(pointer,192).replace('\\','/').casefold() if pointer else ''
        self.validate(key,False)
        return index,path
    def heroes_model_guards(self,sample,api,key):
        self.validate(key);m=self.mem;s=self.server;e=self.engine;p=key.address;vt=m.u32(p)
        if vt!=s+0x8b7100 or m.u32(vt+0x6c)!=s+0x51e370:raise NotReady('该玩家的模型替换方法尚未确认')
        guards=self.heroes_guards(sample)+self.action_guards(key)
        guards.extend(((p,vt),(vt+0x6c,s+0x51e370),(s+0xc59074,api['engine_this']),
                       (s+0xc58fdc,api['model_this']),(api['engine_this'],api['engine_vt']),
                       (api['model_this'],api['model_vt']),(api['engine_vt']+0x14,e+0x173cb0),
                       (api['model_vt']+4,api['get_model']),(api['model_vt']+8,api['lookup'])))
        for offset in (0xf8,0x200):
            value=m.u32(p+offset)
            if offset==0xf8 and value&255:raise PlayerUnavailable('死亡玩家将在复活后切换模型')
            if offset==0x200 and (value>>8)&255 not in (2,3):raise PlayerUnavailable('玩家已转为观战')
            guards.append((p+offset,value))
        if m.i32(p+0xf4)<=0:raise PlayerUnavailable('等待玩家复活')
        return guards

    def verify_combat_damage(self):
        self.heroes_state();m=self.mem;s=self.server
        entry=m.read(s+COMBAT_ENTRY,6);identity=(self.epoch,s,self.engine,entry)
        if getattr(self,'combat_verified',None)==identity:return
        if entry!=COMBAT_PREFIX and not CombatDamageHook.existing(self):raise NotReady('怪物受击入口与此版本不匹配')
        rva,size,digest,relocs=COMBAT_DAMAGE_MANIFEST
        data=bytearray(m.read(s+rva,size))
        for off in relocs:struct.pack_into('<I',data,off,(struct.unpack_from('<I',data,off)[0]-(s-0x10000000))&0xffffffff)
        if hashlib.sha256(data).hexdigest()!=digest:raise NotReady('怪物受击路径与此版本不匹配')
        self.combat_verified=identity
    def verify_combat_targets(self):
        self.heroes_state();self.check_fields(('m_iUserFlag',))
        identity=(self.epoch,self.server)
        if getattr(self,'combat_targets_verified',None)==identity:return
        for rva,data in COMBAT_TARGET_CHECKS:
            if self.mem.read(self.server+rva,len(data))!=data:raise NotReady('怪物目标筛选路径与此版本不匹配')
        self.combat_targets_verified=identity

    def heroes_damage_values(self):
        self.require_local();m=self.mem;s=self.server;values=[]
        for rva,name in zip((0xa134e0,0xa13530),HEROES_DAMAGE):
            obj=s+rva
            if m.u32(obj+8)!=1 or m.string(m.u32(obj+12),80)!=name:raise NotReady('神殿伤害变量未注册')
            parent=m.u32(obj+28)
            if not parent or m.string(m.u32(parent+12),80)!=name:raise NotReady('神殿伤害根变量未确认')
            # +0x24 is the default string; +0x28 is the CURRENT string.
            value=m.string(m.u32(parent+40),64)
            if not re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?',value):raise NotReady('神殿伤害变量不是数值')
            number=float(value)
            if not math.isfinite(number) or not 0<=number<=1000000:raise NotReady('神殿伤害数值异常')
            if m.i32(parent+52)!=int(number):raise NotReady('神殿伤害变量正在同步')
            values.append(value)
        return values
    def probe_feature(self,key):
        if not self.mem or not self.core_verified:raise NotReady('客户端尚未通过兼容性校验')
        if key=='commands':command_entry(self);return
        if key=='chat':self.verify_command('say compatibility_probe');return
        if key=='cheats':command_entry(self);self.require_local();self.cheats_value();return
        self.require_local()
        groups={
            'invulnerable':('m_takedamage',),
            'roster':('m_iHealth','m_iMaxHealth','m_lifeState','m_szNetname'),
            'hp':('m_iHealth','m_iMaxHealth','m_lifeState'),
            'money':('m_iAccount','m_iMaxAccount'),
            'ammo':('m_iClip1','m_iPrimaryAmmoType','m_hMyWeapons','m_iAmmo'),
            'scale':('m_flModelScale','m_flScale','m_flHeadScale','m_flBodyScale'),
            'buy':('m_iUserFlag',),
        }
        if key=='weapon_spawn':self.prepare_weapon_spawn('weapon_ak47');return
        if key=='heroes':self.heroes_state();return
        if key=='heroes_upgrade':self.heroes_enchants();return
        if key=='heroes_model':self.heroes_model_api();return
        if key=='heroes_custom_damage':self.verify_combat_damage();return
        if key=='heroes_no_attack':self.verify_combat_targets();return
        if key=='ghost':self.require_ghost();return
        if key in groups:
            self.check_fields(groups[key])
            if key!='roster':self.check_fields(groups['roster'])
            if key=='buy' and self.mem.read(self.server+0x8d990,19)!=bytes.fromhex('8b81e006000023442404f7d81bc0f7d8c20400'):
                raise NotReady('购买区标志读取路径未验证')
            if key=='buy':self.probe_buy_time()
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
            ('commands','chat','local_commands','roster','hp','money','ammo','scale','buy','invulnerable','cheats','ghost','mutation','mutation_read','machine','heroes','heroes_upgrade','heroes_model','heroes_custom_damage','heroes_no_attack','weapon_spawn')}
        return self.capabilities
    def require(self,key):
        status=probe_result(lambda:self.probe_feature(key));self.capabilities[key]=status
        if not status['available']:raise NotReady(status['reason'])
    def command_status(self,text):
        def check():
            if bot_stop_target(text) is not None:self.prepare_bot_stop()
            else:self.verify_command(text)
        return probe_result(check)
    def bot_stop_value(self):
        self.require('local_commands')
        entry=self.catalog.get('bot_stop')
        if not entry or entry['kind']!='variable':raise NotReady('bot_stop 原生变量未登记')
        for source in entry['sources']:
            module=source['module']
            if module not in self.mods or module=='server.dll' and not self.server:continue
            obj=self.mods[module][0]+source['rva'];m=self.mem
            try:
                if m.u32(obj+8)!=1 or m.string(m.u32(obj+12),64)!='bot_stop':continue
                parent=m.u32(obj+28)
                if m.string(m.u32(parent+12),64)!='bot_stop':continue
                floating,value=struct.unpack('<fi',m.read(parent+48,8))
                if not math.isfinite(floating) or floating!=float(value):continue
                return value
            except Exception:continue
        raise NotReady('bot_stop 当前原生数值未验证')
    def prepare_bot_stop(self):
        # An off sv_cheats is a satisfiable prerequisite, not an unavailable button.
        self.require('cheats');self.bot_stop_value()
    def prepare_weapon_spawn(self,name):
        self.require_local()
        if name not in {row['name'] for row in DATA['weapons']} or not re.fullmatch(r'weapon_[a-zA-Z0-9_]+',name):
            raise ValueError('请从武器列表选择有效武器')
        command='ent_create '+name
        self.verify_command(command,allow_spawn_cheats_setup=True)
        self.require('cheats')
        return command
    def verify_command(self,text,allow_spawn_cheats_setup=False):
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
                    if self.mem.u32(obj+20)&0x4000 and not self.cheats_value():
                        if not (allow_spawn_cheats_setup and name=='ent_create'):continue
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
    def round_sample(self):
        self.require_local();m=self.mem;s=self.server
        for rva,name,offset in ((0x9aa0b0,'m_iTotalRoundsPlayed',0x2f4),
                                (0x9aa0e4,'m_fRoundStartTime',0x304),(0x9aa284,'m_bFreezePeriod',0x2fc)):
            if m.string(m.u32(s+rva),64)!=name or m.u32(s+rva+4)!=offset:raise NotReady('回合字段尚未验证：'+name)
        rules=m.u32(s+0xc5907c);raw=m.read(rules+0x2f4,20)
        count=struct.unpack_from('<i',raw)[0];freeze=raw[8];started=struct.unpack_from('<f',raw,16)[0]
        if not 0<=count<=10000000 or freeze not in (0,1) or not math.isfinite(started) or not 0<=started<1e9:
            raise NotReady('等待有效的回合状态')
        if m.u32(s+0xc5907c)!=rules:raise NotReady('回合正在切换')
        return ((self.epoch,self.map_name,rules),count,raw[16:20],freeze)
    def teleport_player(self,key):
        player=self.validate(key,False)
        if player.team not in (2,3) or re.sub(r'[\s_\-]+','',player.name).casefold() in ('cso2tv','sourcetv','hltv'):
            raise PlayerUnavailable('已跳过观战或电视实体')
        # Server datamap: FIELD_SHORT m_nModelIndex. Death does not remove
        # the player's model; a zero model belongs to a non-character entity.
        field_check(self.mem,self.server,[(0x9bff78,'m_nModelIndex',0x86,4)])
        if player.alive and struct.unpack('<h',self.mem.read(key.address+0x86,2))[0]<=0:
            raise PlayerUnavailable('已跳过无模型实体')
        self.validate(key,False);return player
    def client_corpse(self,player):
        if player.alive:return None,[]
        m=self.mem;c=self.client
        entry=c+15615276+player.key.index*16
        cp,serial=struct.unpack('<II',m.read(entry,8))
        if not cp or (serial&0x3ff)!=(player.key.serial&0x3ff):raise PlayerUnavailable('死者客户端身份尚未同步')
        if m.string(m.u32(c+0x1d00cf4),64)!='m_hRagdoll' or m.u32(c+0x1d00d20)!=0x1688:
            raise NotReady('客户端尸体句柄字段未确认')
        owner=(serial<<16)|player.key.index;handle=m.u32(cp+0x1688)
        guards=[(entry,cp),(entry+4,serial),(cp+0x1688,handle)]
        found=[]
        # Prefer the player's current handle. The owner scan supports a client
        # corpse still present after the server has released its ragdoll handle.
        entries=m.read(c+15615276,8192*16)
        indices=[handle&0xffff] if handle not in (0,0xffffffff) and 64<(handle&0xffff)<8192 else []
        indices+=list(range(65,8192))
        seen=set()
        for index in indices:
            if index in seen:continue
            seen.add(index);address,actual=struct.unpack_from('<II',entries,index*16)
            if not address:continue
            try:
                if m.u32(address)!=c+0xca139c or m.u32(address+0xde8)!=owner:continue
                rag=m.u32(address+0x5d4)
                if not rag:continue
                if m.u32(rag)!=c+0xc80abc:continue
                count=m.u32(rag+4)
                if not 1<=count<=24:continue
                found.append((index,address,actual,rag,count))
                if handle==((actual<<16)|index):break
            except OSError:continue
        if not found:raise PlayerUnavailable('该死者当前没有已生成的实体尸体；不会使用玩家残留坐标')
        if len(found)!=1:raise PlayerUnavailable('该死者存在多个尸体，当前句柄未能唯一确认')
        index,address,actual,rag,count=found[0]
        centry=c+15615276+index*16
        guards.extend(((centry,address),(centry+4,actual),(address,c+0xca139c),
                       (address+0xde8,owner),(address+0x5d4,rag),(rag,c+0xc80abc),(rag+4,count)))
        v=self.mods.get('vphysics.dll',(0,0,''))[0]
        if not v:raise NotReady('物理模块尚未加载')
        methods={'get_origin':c+0x912cd0,'set_origin':c+0x836d50,
                 'get_matrix':v+0x1eda0,'set_matrix':v+0x1f5f0,'set_velocity':v+0x1f7c0,'wake':v+0x1d770}
        signatures=((methods['get_origin'],'568b711c578db9dc0200008bce6a008b16'),
                    (methods['set_origin'],'558bec83e4f8515356578bf1'),
                    (methods['get_matrix'],'558bec83e4f881ec800000008b4908'),
                    (methods['set_matrix'],'558bec83e4f881ecb8000000568bf157'),
                    (methods['set_velocity'],'558bec568bf18b068b4028ffd0'),
                    (methods['wake'],'8b4908e948b80200'))
        for at,signature in signatures:
            raw=bytes.fromhex(signature)
            if m.read(at,len(raw))!=raw:raise NotReady('尸体物理接口与已验证版本不符')
        objects=[];checked=set()
        for i in range(count):
            at=rag+0x1c+i*0x18;obj=m.u32(at);vt=m.u32(obj)
            guards.extend(((at,obj),(obj,vt)))
            if not v<=vt<v+self.mods['vphysics.dll'][1]:raise NotReady('尸体骨骼不属于物理模块')
            if vt not in checked:
                for slot,name in ((0xc0,'get_matrix'),(0xb8,'set_matrix'),(0xc8,'set_velocity'),(0x60,'wake')):
                    if m.u32(vt+slot)!=methods[name]:raise NotReady('尸体骨骼原生方法未确认')
                    guards.append((vt+slot,methods[name]))
                checked.add(vt)
            objects.append(obj)
        if len(set(objects))!=count:raise NotReady('尸体骨骼列表正在变化')
        origin=struct.unpack('<3f',m.read(rag+0x2dc,12))
        if not all(math.isfinite(x) and abs(x)<1000000 for x in origin):raise NotReady('尸体物理位置无效')
        return dict(address=address,rag=rag,objects=objects,origin=origin,**methods),guards
    def teleport_ragdoll(self,player):
        if player.alive:return None,[]
        m=self.mem;s=self.server;p=player.key.address
        field_check(m,s,[(0x9f446c,'m_hRagdoll',0x2140,4),
                         (0x9f49b0,'m_hPlayer',0x70c,4),
                         (0x9f4a18,'m_vecRagdollOrigin',0x71c,4)])
        handle=m.u32(p+0x2140)
        if handle in (0,0xffffffff):return None,[(p+0x2140,handle)]
        index=handle&0xffff;serial=handle>>16
        if not 64<index<8192:raise PlayerUnavailable('死亡模型编号尚未同步')
        entry=s+0xa5fa44+index*16;address,actual=struct.unpack('<II',m.read(entry,8))
        if not address or actual!=serial:raise PlayerUnavailable('死亡模型已移除或正在更新')
        owner=(player.key.serial<<16)|player.key.index
        if m.u32(address)!=s+0x8b79a0 or m.u32(address+0x70c)!=owner:
            raise PlayerUnavailable('死亡模型与玩家身份不匹配')
        origin=struct.unpack('<3f',m.read(address+0x71c,12))
        if not all(math.isfinite(v) and abs(v)<1000000 for v in origin):raise NotReady('死亡模型位置尚未就绪')
        guards=[(p+0x2140,handle),(entry,address),(entry+4,serial),
                (address,s+0x8b79a0),(address+0x70c,owner)]
        return (address,origin),guards
    def player_operation(self,operation,key,ordinal=0):
        self.require_local();player=self.validate(key,False)
        if player.local:raise ValueError('不能对自己执行此操作')
        if player.team not in (2,3):raise ValueError('观战或电视实体不能作为此操作目标')
        if operation=='kick':
            name=player.name
            if any(ch in name for ch in ('"',';','\r','\n','\0','\\')) or any(ord(ch)<32 for ch in name):
                raise ValueError('该昵称不能安全用于原生踢人命令')
            players=[self.read_player(index) for index in range(1,65)]
            if sum(p is not None and p.name.casefold()==name.casefold() for p in players)!=1:
                raise ValueError('存在重名玩家，不能按昵称踢出')
            self.validate(key,False);self.send('kick "'+name+'"');return
        if operation in ('goto','bring'):
            player=self.teleport_player(key)
            local=self.read_player(self.local_index)
            if local is None:raise NotReady('本地角色尚未同步')
            self.teleport_player(local.key)
            mover=local if operation=='goto' else player;anchor=player if operation=='goto' else local
            anchor_corpse,anchor_guards=self.client_corpse(anchor)
            mover_corpse,mover_guards=self.client_corpse(mover)
            try:mover_body,body_guards=self.teleport_ragdoll(mover)
            except PlayerUnavailable:
                if not mover_corpse:raise
                mover_body=None
                body_guards=[(mover.key.address+0x2140,self.mem.u32(mover.key.address+0x2140))]
            origin=anchor_corpse['origin'] if anchor_corpse else self.player_origin(anchor.key)
            # A dead player's server entity is hidden and is not its corpse.
            # Moving it was the source of false success and wrong destinations.
            # Use the registered native Teleport method on GameFrame. Console
            # cheat flags and bot_stop are unrelated to this host-only call.
            entry=next(s for s in self.catalog['ent_teleport']['sources'] if s['module']=='server.dll')
            command=self.server+entry['rva']
            if self.mem.u32(command+8)!=1 or self.mem.string(self.mem.u32(command+12),64)!='ent_teleport':
                raise NotReady('原生传送登记未确认')
            callback=self.mem.u32(command+24)
            if not self.server<=callback<self.server+self.mods['server.dll'][1]:raise NotReady('原生传送入口无效')
            code=self.mem.read(callback,80);slots=re.findall(rb'\x8b\x01\xff\x90(.{4})',code,re.DOTALL)
            if len(slots)!=1:raise NotReady('原生传送调用约定尚未确认')
            slot=struct.unpack('<I',slots[0])[0];vtable=self.mem.u32(mover.key.address);fn=self.mem.u32(vtable+slot)
            if slot>0x1000 or slot%4 or not self.server<=fn<self.server+self.mods['server.dll'][1]:raise NotReady('玩家传送方法未确认')
            self.validate(key,False);self.validate(local.key,False)
            guards=self.action_guards(key,local.key)+anchor_guards+mover_guards+body_guards
            body_fn=body_edict=None
            if mover_body:
                body_vtable=self.mem.u32(mover_body[0]);body_fn=self.mem.u32(body_vtable+slot)
                if not self.server<=body_fn<self.server+self.mods['server.dll'][1]:raise NotReady('服务端尸体传送入口未确认')
                body_index=self.mem.u32(mover.key.address+0x2140)&0xffff
                body_edict=self.network_target(mover_body[0],body_index)
                guards.extend(((body_vtable+slot,body_fn),(mover_body[0]+0x20,body_edict),
                               (body_edict+4,self.mem.u32(body_edict+4))))
            if not mover_corpse:guards.extend(((mover.key.address,vtable),(vtable+slot,fn)))
            def build(remote):
                call=lambda _:teleport_code(remote,
                    (((mover_body[0],body_fn),) if mover_body else ()) if mover_corpse else ((mover.key.address,fn),),
                    body=mover_body[0] if mover_body else None,body_edict=body_edict,
                    anchor=anchor_corpse,corpse=mover_corpse)
                return (player_action_stub(remote,guards,call,TP_CODE)+
                        teleport_payload(origin,mover_corpse))
            self.submit_player_native(build,result_offset=TP_STATUS);return
        if operation=='vote':
            name=player.name.encode('utf-8')
            if not name or len(name)>180:raise ValueError('玩家昵称长度无效')
            matches=[self.read_player(i) for i in range(1,65)]
            if sum(p is not None and p.name==player.name for p in matches)!=1:raise ValueError('存在重名玩家，不能发起指定玩家投票')
            callback=vote_callback(self);guards=self.action_guards(key);self.validate(key,False)
            def build(remote):
                data=bytearray(160+len(name)+1);struct.pack_into('<II',data,8,remote+544,2)
                struct.pack_into('<II',data,32+12,6,remote+672)
                struct.pack_into('<II',data,64+12,6,remote+608)
                data[96:106]=b'Host vote\0';data[160:]=name+b'\0'
                call=lambda r:b'\x68'+struct.pack('<I',r+512)+b'\xb8'+struct.pack('<I',callback)+b'\xff\xd0\x83\xc4\x04'
                return player_action_stub(remote,guards,call)+data
            self.submit_player_native(build);return
        raise ValueError('未知玩家操作')
    def player_origin(self,key):
        self.validate(key,False)
        m=self.mem;p=key.address
        descriptor=self.server+0x9c0938
        if m.string(m.u32(descriptor),64)!='m_vecAbsOrigin':raise NotReady('玩家位置字段尚未验证')
        offset=m.u32(descriptor+4)
        if not 0x100<=offset<=0x800:raise NotReady('玩家位置字段异常')
        origin=struct.unpack('<3f',m.read(p+offset,12))
        if not all(math.isfinite(v) and abs(v)<1000000 for v in origin):raise NotReady('玩家位置尚未就绪')
        self.validate(key,False);return origin
    def action_guards(self,*keys):
        guards=[]
        for key in keys:
            entry=self.server+0xa5fa44+key.index*16;guards.extend(((entry,key.address),(entry+4,key.serial)))
        guards.append((self.engine+9249476,6));return guards
    def submit_player_native(self,build,result_offset=None):
        if self.player_queue is None:self.player_queue=PlayerActionQueue(self)
        self.player_queue.submit_native(build,result_offset=result_offset)
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
        identity=m.read(entry,8);p,serial=struct.unpack('<II',identity)
        if not p:return None
        try:
            if m.string(m.u32(p+0x70),32)!='player':return None
            maximum,hp=struct.unpack('<ii',m.read(p+0xf0,8));life=m.read(p+0xf8,1)[0];team=m.read(p+0x201,1)[0]
            damage_mode=None;ghost_alpha=None
            if team==2 and self.capabilities.get('ghost',{}).get('available',False):
                try:ghost_alpha=m.read(p+0x8b,1)[0]
                except (OSError,NotReady,IndexError):pass
            if self.capabilities.get('invulnerable',{}).get('available',False):
                try:
                    sample=m.read(p+0xf9,1)[0]
                    if sample in (0,1,2,3):damage_mode=sample
                except (OSError,NotReady,IndexError):pass
            money=m.i32(p+0x1c3c) if probe_result(lambda:self.check_fields(('m_iAccount','m_iMaxAccount')))['available'] else -1;name=m.string(p+0xed0,48)
        except OSError:
            # A disappearing entity is not a broken process connection. A read
            # error on the SAME identity remains a real error and is reported.
            if m.read(entry,8)!=identity:return None
            raise
        if m.read(entry,8)!=identity:return None
        if not -1000000<=hp<=100000000 or not 0<=maximum<=100000000 or team>16:raise NotReady('玩家字段异常，已停止读取')
        key=PlayerKey(self.epoch,self.map_name,index,p,serial)
        return Player(key,name or f'玩家 {index}',hp,maximum,money,team,life==0 and hp>0,index==self.local_index,damage_mode,ghost_alpha)
    def validate(self,key,alive=True):
        if key.epoch!=self.epoch or key.map_name!=self.map_name or self.current_context()!=self.context:raise NotReady('对局已变化，请刷新玩家列表')
        actual=self.read_player(key.index)
        if not actual or actual.key!=key:raise PlayerUnavailable('玩家已离开或编号被复用，请重新勾选')
        if alive and not actual.alive:raise PlayerUnavailable('该玩家已死亡，等待存活后操作')
        return actual
    def network_target(self,p,index):
        m=self.mem
        if m.read(p+0x68,1)!=b'\0':raise PlayerUnavailable('实体正在集中更新，稍后重试')
        edict=m.u32(p+0x20)
        flags,serial,slot=struct.unpack('<Ihh',m.read(edict,8))
        if slot!=index or flags&~0xffff:raise NotReady('实体网络编号不匹配')
        return edict
    def dirty(self,p,index):
        edict=self.network_target(p,index)
        # FL_EDICT_CHANGED | FL_EDICT_FULL: regenerate the entity baseline.
        flags=self.mem.u32(edict)
        self.mem.write(edict,struct.pack('<I',flags|0x101))
    def damage_mode(self,key):
        self.require('invulnerable');self.validate(key)
        value=self.mem.read(key.address+0xf9,1)[0]
        if value not in (0,1,2,3):raise NotReady('伤害接收字段状态异常')
        return value
    def set_damage_mode(self,key,value,expected=None,alive=True):
        # The CE sample's eight-byte health write also cleared m_takedamage.
        # Change only this verified byte; leave health/lifeState/padding intact.
        if value not in (0,1,2,3):raise ValueError('伤害接收状态无效')
        self.require('invulnerable');self.validate(key,alive)
        identity=struct.pack('<II',key.address,key.serial)
        entry=self.server+0xa5fa44+key.index*16
        if self.mem.read(entry,8)!=identity:raise PlayerUnavailable('玩家身份已变化，无敌设置已取消')
        current=self.mem.read(key.address+0xf9,1)[0]
        if current not in (0,1,2,3):raise NotReady('伤害接收字段状态异常')
        if expected is not None and current!=expected:return False
        if current==value:return True
        self.mem.write(key.address+0xf9,bytes([value]))
        if self.mem.read(entry,8)!=identity:raise PlayerUnavailable('玩家身份已变化，等待重新选择')
        if self.mem.read(key.address+0xf9,1)!=bytes([value]):raise NotReady('伤害开关待重新确认')
        return True
    def set_player_field(self,key,offset,data,alive=True,scale=False):
        feature={0xf0:'hp',0xf4:'hp',0x1c3c:'money',0x1c40:'money',0x37c:'scale',0x6ec:'scale',0x6f0:'scale',0x6e0:'buy'}.get(offset)
        if feature is None and 0x75c<=offset<0x7ac and offset%2==0:feature='ammo'
        if feature is None:raise NotReady('字段未登记，拒绝写入')
        self.require(feature)
        self.validate(key,alive);p=key.address
        self.network_target(p,key.index)
        if self.mem.read(p+offset,len(data))==data:return False
        entry=self.server+0xa5fa44+key.index*16;identity=struct.pack('<II',p,key.serial)
        if self.mem.read(entry,8)!=identity:raise PlayerUnavailable('玩家已改变')
        self.mem.write(p+offset,data)
        if self.mem.read(entry,8)!=identity:raise PlayerUnavailable('玩家已改变')
        if scale:self.mem.write(p+0x6fc,b'\x01')
        self.dirty(p,key.index)
        if self.mem.read(entry,8)!=identity:raise PlayerUnavailable('玩家已改变')
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
    def set_scale(self,key,head=None,body=None,uniform=False,factor=1):
        self.require('scale')
        setting=model_scale_setting(head,body,uniform,factor)
        offset,packed=model_scale_payload(setting)
        if setting['uniform']:self.set_player_field(key,offset,packed)
        else:self.set_player_field(key,offset,packed,scale=True)
    def set_buy_flag(self,key,enabled):
        self.require('buy')
        self.validate(key,alive=enabled)
        # CCSPlayer's AddUserFlag callback is a no-op in this exact build.
        # A different subclass must be reviewed before bypassing that callback.
        callback=self.mem.u32(self.mem.u32(key.address)+0x3fc)
        if callback!=self.server+0x8bb00 or self.mem.read(callback,1)!=b'\xc3':raise RuntimeError('当前角色的购买标志回调尚未验证')
        flags=self.mem.u32(key.address+0x6e0)
        self.set_player_field(key,0x6e0,struct.pack('<I',(flags|1) if enabled else (flags&~1)),alive=enabled)
    def buy_time_codes(self):
        # Verified client.dll RVA 0x71EE50: IsBuyTimeElapsed. Change ONLY the
        # aligned JE displacement (+0x11) from +4 to +0. Both branch outcomes
        # then use the existing xor al,al / pop esi / ret path. Server rules,
        # mp_buytime, other clients, death checks and NONE_BUY remain unchanged.
        code=bytearray.fromhex('568bf18b0d54bbcd11e86238a8ff84c0740432c05ec3a1d090e610f30f10480ca1d4d4e810f30f5c4e3c5ef30f10403033c0f30f59059c39da100f2fc80f97c0c3')
        for offset,rva in ((5,0x1cdbb54),(23,0xe690d0),(33,0xe8d4d4),(54,0xda399c)):
            struct.pack_into('<I',code,offset,self.client+rva)
        original=bytes(code);code[0x11]=0
        return original,bytes(code)
    def probe_buy_time(self):
        original,opened=self.buy_time_codes();address=self.client+0x71ee50
        if self.mem.read(address,len(original)) not in (original,opened):raise NotReady('购买菜单时间判断版本尚未验证')
        rules=self.mem.u32(self.client+0x1cdb994)
        if self.mem.u32(self.mem.u32(rules)+0x144)!=address:raise NotReady('当前模式使用其他购买时间判断，等待适配')
        return original,opened
    def set_buy_time_open(self,enabled):
        if enabled:
            self.require_local();original,opened=self.probe_buy_time()
            if self.mem.read(self.client+0x71ee50,len(original))==opened:return
            # Retain ownership BEFORE the write so a partial OS failure can be restored.
            self.buy_time_saved=(self.mem.pid,self.client,original,opened)
            self.mem.write_code_byte(self.client+0x71ee61,b'\x04',b'\x00')
            if self.mem.read(self.client+0x71ee50,len(opened))!=opened:raise NotReady('购买菜单时间判断读回不一致')
            return
        record=self.buy_time_saved
        if record is None:return
        pid,base,original,opened=record
        if not self.mem or self.mem.pid!=pid or self.mods.get('client.dll',(None,))[0]!=base:
            self.buy_time_saved=None;return
        current=self.mem.read(base+0x71ee50,len(original))
        if current==opened:
            self.mem.write_code_byte(base+0x71ee61,b'\x00',b'\x04')
            if self.mem.read(base+0x71ee50,len(original))!=original:raise NotReady('购买菜单时间判断恢复待重试')
        # Leave any later third-party change untouched; do not claim ownership of it.
        self.buy_time_saved=None
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
    def require_ghost(self):
        self.require_local()
        if self.current_context()!=self.context:raise NotReady('对局已变化')
        if self.mode_id()!=4:raise NotReady('幽灵显形仅适用于幽灵模式')
        self.check_ghost_fields()
    def check_ghost_fields(self):
        field_check(self.mem,self.server,GHOST_FIELDS)
        if self.mem.read(self.server+0x52aa00,len(GHOST_SET_SIGNATURE))!=GHOST_SET_SIGNATURE:
            raise NotReady('幽灵参数原生设置路径未验证')
    def set_ghost_params(self,key,data,expected=None):
        if len(data)!=7:raise ValueError('幽灵参数长度异常')
        self.require_local();player=self.validate(key,False)
        self.check_ghost_fields()
        mode=self.mode_id()
        if expected is None:
            if mode!=4:raise NotReady('幽灵显形仅适用于幽灵模式')
            if not player.alive or player.team!=2:raise PlayerUnavailable('目标不是存活幽灵')
        elif mode!=4 or player.team!=2:
            # A new mode/team owns its own defaults, which may also be 255.
            return False
        p=key.address;entry=self.server+0xa5fa44+key.index*16
        identity=struct.pack('<II',p,key.serial)
        if self.mem.read(entry,8)!=identity:raise PlayerUnavailable('玩家身份已变化')
        current=self.mem.read(p+0x12ac,7)
        if expected is not None and current!=expected:return False
        if current==data:return True
        self.network_target(p,key.index)
        self.mem.write(p+0x12ac,data)
        if self.mem.read(entry,8)!=identity:raise PlayerUnavailable('玩家身份已变化')
        self.dirty(p,key.index)
        if self.mem.read(entry,8)!=identity:raise PlayerUnavailable('玩家身份已变化')
        if self.mem.read(p+0x12ac,7)!=data:raise NotReady('幽灵参数被游戏覆盖，稍后重试')
        return True
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
        errors=[]
        if self.mem and self.buy_time_saved is not None:
            try:self.set_buy_time_open(False)
            except Exception as ex:errors.append(ex)
        for resource in (self.queue,self.player_queue,self.mem):
            if resource is not None:
                try:resource.close()
                except Exception as ex:errors.append(ex)
        self.queue=None;self.player_queue=None;self.mem=None
        self.mods={};self.server=0;self.context=None;self.epoch+=1
        self.core_verified=False;self.capabilities={};self.next_modules=0.
        if errors:raise errors[0]

def bounded_int(value,low,high,label):
    try:number=int(str(value).strip())
    except (ValueError,TypeError):raise ValueError(f'{label}必须是整数') from None
    if not low<=number<=high:raise ValueError(f'{label}范围 {low}～{high}')
    return number

def model_scale_factor(value,label="倍率"):
    """Accept positive float32 factors without an arbitrary gameplay range."""
    try:number=float(value)
    except (ValueError,TypeError):raise ValueError(label+'必须是数字') from None
    if not math.isfinite(number) or number<=0:raise ValueError(label+'必须是有限正数')
    try:stored=struct.unpack('<f',struct.pack('<f',number))[0]
    except (OverflowError,struct.error):raise ValueError('倍率超出游戏单精度浮点数的表示范围') from None
    if not math.isfinite(stored) or stored<=0:raise ValueError('倍率在游戏单精度浮点数中溢出或下溢为零')
    return stored

def model_scale_setting(head=None,body=None,uniform=False,factor=1):
    if uniform:return {'uniform':True,'factor':model_scale_factor(factor,'整体倍率')}
    setting={'uniform':False,'head':model_scale_factor(head,'头部倍率'),'body':model_scale_factor(body,'身体倍率')}
    model_scale_payload(setting)  # Validate the relative ratio before changing any live fields.
    return setting

def model_scale_payload(setting):
    if setting['uniform']:return 0x37c,struct.pack('<f',setting['factor'])
    # client+0x76BB30: native BodyScale scales only bone cross-sections,
    # while m_flScale scales all three axes AND bone translations.
    # B globally + H/B around the head pivot gives absolute H and B,
    # without reapplying B to the body's width or changing ModelScale.
    body=setting['body'];relative=model_scale_factor(setting['head']/body,'头部 / 身体相对倍率')
    return 0x6ec,struct.pack('<fff',body,relative,1.0)

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

def can_set_player_values(player):
    return (player.alive and player.team in (2,3) and
            re.sub(r'[\s_\-]+','',player.name).casefold() not in ('cso2tv','sourcetv','hltv'))


class Controls:
    """Identity-bound locks. Disable restores limits/scale, never old health or cash."""
    def __init__(self,backend,caps):
        self.b=backend;self.caps=caps;self.keys=[];self.hp=None;self.money=None;self.ammo=False;self.scale=None;self.saved={};self.buy=False;self.buy_saved={}
        self.invulnerable=False;self.damage_saved={};self.buy_time_active=False
        self.ghost=False;self.ghost_keys=set();self.ghost_saved={};self.ghost_next_at=0.
        self.invulnerable_keys=[];self.invulnerable_auto=True;self.invulnerable_done=set()
    def disable_unavailable(self):
        for key in ('hp','money','ammo','scale','buy','invulnerable','ghost'):
            if not self.b.capabilities.get(key,{}).get('available',False):
                setattr(self,key,False if key in ('ammo','buy','invulnerable','ghost') else None)
    def remember(self,key,field,size):
        self.b.validate(key)  # Recheck identity before reading an old snapshot's address.
        record=(key,field)
        if record not in self.saved:self.saved[record]=[self.b.mem.read(key.address+field,size),None]
        return self.saved[record]
    def configure_value_locks(self,keys,hp_enabled,money_enabled):
        keys=list(dict.fromkeys(keys));players={}
        for key in keys:
            try:players[key]=self.b.validate(key,False)
            except PlayerUnavailable:continue
        keys=[key for key in keys if key in players]
        updates={}
        for field,enabled in (('hp',hp_enabled),('money',money_enabled)):
            if not enabled:updates[field]=None;continue
            self.b.require(field)
            previous=getattr(self,field) or {};values={}
            for key,player in players.items():
                if key in previous:values[key]=previous[key]
                elif can_set_player_values(player):
                    values[key]=bounded_int(player.health if field=='hp' else player.money,
                                            1 if field=='hp' else 0,999999,'当前数值')
            updates[field]=values
        self.keys=keys;self.hp=updates['hp'];self.money=updates['money']
        errors=self.restore_value_limits()
        if errors:raise RuntimeError('锁定已更新，旧临时上限仍待恢复：'+errors[0])
    def restore_value_limits(self):
        errors=[]
        for field,offset in (('hp',0xf0),('money',0x1c40)):
            owned=set(self.keys) if getattr(self,field) is not None else set()
            removed={key for key,at in self.saved if at==offset}-owned
            errors+=self.restore({offset},keys=removed)
        return errors
    def apply_value(self,field,key,value):
        values=getattr(self,field);locked=values is not None and key in self.keys
        if locked:
            offset=0xf0 if field=='hp' else 0x1c40
            rec=self.remember(key,offset,4)
            maximum=value if field=='hp' else max(value,self.b.mem.i32(key.address+offset))
            rec[1]=struct.pack('<i',maximum)
            # Update ownership before the write: a partial write must never be
            # followed by the old lock value on the next worker iteration.
            values[key]=value
        (self.b.set_health if field=='hp' else self.b.set_money)(key,value)
    def step(self,players):
        valid={p.key for p in players};live={p.key:p for p in players if p.alive};self.keys=[k for k in self.keys if k in valid]
        for field in ('hp','money'):
            values=getattr(self,field)
            if values is not None:
                for key in set(values)-set(self.keys):values.pop(key,None)
        # Drop restoration ownership only after a fresh, stable roster proves
        # the old entity is gone. Dead players still retain restoration records.
        self.saved={record:value for record,value in self.saved.items() if record[0] in valid}
        self.buy_saved={key:value for key,value in self.buy_saved.items() if key in valid}
        self.damage_saved={key:value for key,value in self.damage_saved.items() if key in valid}
        ghost_keys={p.key for p in players if p.team==2}
        self.ghost_keys.intersection_update(ghost_keys)
        if self.ghost and not self.ghost_keys:self.ghost=False
        self.ghost_saved={key:value for key,value in self.ghost_saved.items() if key in ghost_keys}
        self.invulnerable_keys=[key for key in self.invulnerable_keys if key in valid]
        self.invulnerable_done.intersection_update(valid)
        count=0
        if self.invulnerable:
            for key in self.invulnerable_keys:
                if key not in live or (not self.invulnerable_auto and key in self.invulnerable_done):continue
                try:
                    if key not in self.damage_saved:self.damage_saved[key]=self.b.damage_mode(key)
                    self.b.set_damage_mode(key,0);self.invulnerable_done.add(key);count+=1
                except PlayerUnavailable:continue
        if self.ghost and time.monotonic()>=self.ghost_next_at:
            self.ghost_next_at=time.monotonic()+.2
            self.b.require_ghost()
            for key,player in live.items():
                if player.team!=2 or key not in self.ghost_keys:continue
                try:
                    self.b.validate(key)
                    original=self.b.mem.read(key.address+0x12ac,7)
                    if original!=GHOST_VISIBLE:
                        fade=struct.unpack_from('<f',original)[0]
                        if not math.isfinite(fade):raise NotReady('幽灵透明度参数异常')
                        # A native respawn/reset replaces the prior round's parameters.
                        # Preserve that new baseline before applying visibility again.
                        self.ghost_saved[key]=original
                        self.b.set_ghost_params(key,GHOST_VISIBLE)
                    count+=1
                except PlayerUnavailable:continue
        for key in self.keys:
            if key not in live or not can_set_player_values(live[key]):continue
            try:
                for field in ('hp','money'):
                    values=getattr(self,field)
                    if values is None:continue
                    if key not in values:
                        player=self.b.validate(key,False)
                        if not can_set_player_values(player):continue
                        values[key]=bounded_int(player.health if field=='hp' else player.money,
                                                1 if field=='hp' else 0,999999,'当前数值')
                    value=values[key]
                    if field=='hp' and self.b.mem.i32(key.address+0xf0)>=value:
                        # Locking existing HP must preserve the player's maximum.
                        self.b.set_player_field(key,0xf4,struct.pack('<i',value))
                    else:self.apply_value(field,key,value)
                    count+=1
            except PlayerUnavailable:continue
        for key in live:
            try:
                if self.ammo:self.b.refill(key,self.caps);count+=1
                if self.scale:
                    setting=self.scale
                    offset,packed=model_scale_payload(setting)
                    rec=self.remember(key,offset,len(packed));rec[1]=packed
                    self.b.set_scale(key,**setting);count+=1
                if self.buy and live[key].local:
                    self.b.validate(key)
                    if key not in self.buy_saved:self.buy_saved[key]=self.b.mem.u32(key.address+0x6e0)&1
                    self.b.set_buy_flag(key,True);count+=1
                    self.buy_time_active=True;self.b.set_buy_time_open(True)
            except PlayerUnavailable:continue
        return count
    def step_isolated(self,players):
        features=('hp','money','ammo','scale','buy','invulnerable','ghost');values={key:getattr(self,key) for key in features};errors=[]
        try:
            for key in features:
                for other in features:setattr(self,other,values[other] if other==key else (False if other in ('ammo','buy','invulnerable','ghost') else None))
                if values[key] is None or values[key] is False:continue
                try:
                    self.step(players)
                    if key=='ghost':values[key]=self.ghost
                except Exception as ex:
                    values[key]=False if key in ('ammo','buy','invulnerable','ghost') else None
                    errors.append(key+' 已停止：'+str(ex))
        finally:
            for key,value in values.items():setattr(self,key,value)
        return errors
    def configure_invulnerability(self,keys,auto=True):
        keys=list(dict.fromkeys(keys))
        if keys:self.b.require('invulnerable')
        for key in keys:self.b.validate(key,False)
        removed=set(self.damage_saved)-set(keys)
        errors=self.restore_invulnerability(removed)
        if errors:raise RuntimeError('旧无敌对象仍待恢复：'+errors[0])
        self.invulnerable_keys=keys;self.invulnerable_auto=bool(auto)
        self.invulnerable_done.clear();self.invulnerable=bool(keys)
    def restore_invulnerability(self,keys=None):
        errors=[]
        for key,before in list(self.damage_saved.items()):
            if keys is not None and key not in keys:continue
            try:self.b.set_damage_mode(key,before,expected=0,alive=False)
            except Exception as ex:errors.append(str(ex))
            else:self.damage_saved.pop(key,None)
        return errors
    def restore_ghost(self,keys=None):
        errors=[]
        for key,original in list(self.ghost_saved.items()):
            if keys is not None and key not in keys:continue
            try:self.b.set_ghost_params(key,original,expected=GHOST_VISIBLE)
            except PlayerUnavailable:self.ghost_saved.pop(key,None)
            except Exception as ex:errors.append(str(ex))
            else:self.ghost_saved.pop(key,None)
        return errors
    def configure_ghost(self,keys,enabled):
        self.b.require_ghost()
        targets=set()
        for key in keys:
            try:player=self.b.validate(key,False)
            except PlayerUnavailable:continue
            if player.alive and player.team==2 and re.sub(r'[\s_\-]+','',player.name).casefold() not in ('cso2tv','sourcetv','hltv'):
                targets.add(key)
        if not targets:raise NotReady('请选择存活的 T 阵营幽灵')
        if enabled:
            self.ghost_keys.update(targets);self.ghost_next_at=0.
        else:self.ghost_keys.difference_update(targets)
        self.ghost=bool(self.ghost_keys)
        errors=[] if enabled else self.restore_ghost(targets)
        if errors:raise RuntimeError('幽灵原参数仍待恢复，将继续重试：'+errors[0])
        return len(targets)
    def restore_buy(self):
        errors=self.restore_buy_time()
        for key,before in list(self.buy_saved.items()):
            try:
                if not before:self.b.set_buy_flag(key,False)
            except Exception as ex:errors.append(str(ex))
            else:self.buy_saved.pop(key,None)
        return errors
    def restore_buy_time(self):
        if not self.buy_time_active:return []
        try:self.b.set_buy_time_open(False)
        except Exception as ex:return [str(ex)]
        self.buy_time_active=False;return []
    def restore(self,fields=None,keys=None):
        errors=[]
        for (key,field),(before,written) in list(self.saved.items()):
            if fields is not None and field not in fields:continue
            if keys is not None and key not in keys:continue
            try:
                self.b.validate(key,False)
                if written is not None and self.b.mem.read(key.address+field,len(written))==written:
                    self.b.set_player_field(key,field,before,alive=False,scale=field in (0x6ec,0x6f0))
            except Exception as ex:errors.append(str(ex))
            else:self.saved.pop((key,field),None)
        return errors
    def retry_restores(self):
        fields=set()
        if self.scale is None:fields.update((0x37c,0x6ec,0x6f0))
        errors=self.restore(fields)+self.restore_value_limits()
        if not self.buy:errors+=self.restore_buy()
        if not self.invulnerable:errors+=self.restore_invulnerability()
        if not self.ghost:self.ghost_keys.clear()
        errors+=self.restore_ghost(set(self.ghost_saved)-self.ghost_keys)
        return errors
    def stop(self,restore=True):
        self.hp=self.money=self.scale=None;self.ammo=False;self.buy=False;self.invulnerable=False;self.ghost=False;self.ghost_next_at=0.;self.keys=[]
        self.invulnerable_keys=[];self.invulnerable_done.clear()
        self.ghost_keys.clear()
        errors=self.restore() if restore else []
        if restore:errors+=self.restore_buy();errors+=self.restore_invulnerability();errors+=self.restore_ghost()
        if not restore:
            # Entity identities expire on map changes; the client code patch does not.
            errors+=self.restore_buy_time();self.buy_saved.clear();self.saved.clear();self.damage_saved.clear();self.ghost_saved.clear()
        return errors

class RoundSettings:
    """One successful application per selected identity and native round."""
    def __init__(self,backend,clock=time.monotonic):
        self.b=backend;self.clock=clock;self.jobs={};self.sample=None;self.generation=0;self.ready_at=0.
    def clear(self):self.jobs.clear();self.sample=None;self.generation=0;self.ready_at=0.
    def configure(self,field,keys,value):
        if field not in ('hp','money'):raise ValueError('未知数值类型')
        if value is None:self.jobs.pop(field,None);return
        if not keys:raise ValueError('请先勾选玩家')
        value=bounded_int(value,1 if field=='hp' else 0,999999,'数值')
        self.b.require(field);self.b.round_sample()
        for key in keys:self.b.validate(key,False)
        self.jobs[field]=dict(keys=set(keys),value=value,done=set())
    def step(self,players):
        if not self.jobs:return []
        sample=self.b.round_sample();old=self.sample
        changed=(old is None or sample[0]!=old[0] or sample[1]!=old[1] or
                 (sample[3] and not old[3]) or (not sample[3] and not old[3] and sample[2]!=old[2]))
        if changed:
            self.generation+=1;self.ready_at=self.clock()+.25
            for job in self.jobs.values():job['done'].clear()
        self.sample=sample
        valid={p.key:p for p in players}
        for job in self.jobs.values():job['keys'].intersection_update(valid)
        if self.clock()<self.ready_at:return []
        messages=[]
        for field,job in list(self.jobs.items()):
            try:
                for key in sorted(job['keys']-job['done'],key=lambda k:k.index):
                    if not can_set_player_values(valid[key]):continue
                    if self.b.round_sample()!=sample:break
                    try:
                        if not can_set_player_values(self.b.validate(key,False)):continue
                        (self.b.set_health if field=='hp' else self.b.set_money)(key,job['value'])
                    except PlayerUnavailable:continue
                    job['done'].add(key)
                    messages.append(f'每局设置 {field}：#{key.index} = {job["value"]}')
            except Exception as ex:
                self.jobs.pop(field,None);messages.append(f'每局设置 {field} 已停止：{ex}')
        return messages

class Worker(threading.Thread):
    def __init__(self,events,caps):
        super().__init__(name='CSO2 host worker',daemon=True)
        self.events=events;self.requests=queue.Queue(maxsize=128);self.quit=threading.Event();self.b=Backend();self.controls=Controls(self.b,caps);self.request_lock=threading.Lock();self.request_generation=0
        self.players=[];self.chat=None;self.last_context=None;self.tick_error='';self.last_ui=0;self.bio_pending=None;self.restore_error='';self.command_watch=[];self.bot_stop_pending=None
        self.teleport_jobs=[];self.teleport_active=None
        self.heroes=HeroesControls(self.b,self.emit);self.combat=HeroesCombatControls(self.b,self.emit);self.ground_spawn_pending=None
        self.each_round=False;self.auto_paused=False;self.cheats_desired=False;self.cheats_applied=None;self.cheats_next_at=0.;self.cheats_auto_error=''
        self.feature_preferences={};self.features_applied=set();self.features_round=None
        self.round_settings=RoundSettings(self.b)
        self.auto_connect=False;self.connection_game=None;self.connection_generation=0
        self.next_connect=0.;self.connect_error='';self.retry_interval=1.5
        self.next_candidate_check=0.
    def emit(self,kind,**data):self.events.put((kind,data))
    def emit_flags(self):
        self.emit('ghost_targets',keys=list(self.controls.ghost_keys) if self.controls.ghost else [])
        self.emit('flags',heroes_temple=self.heroes.protected)
        self.heroes.flags();self.combat.flags()
        self.emit('flags',hp=self.controls.hp is not None,money=self.controls.money is not None,invulnerable=self.controls.invulnerable,ammo=self.controls.ammo,scale=self.controls.scale is not None,buy=self.controls.buy,chat=self.chat is not None,round_hp='hp' in self.round_settings.jobs,round_money='money' in self.round_settings.jobs)
    def submit(self,action,**data):
        with self.request_lock:
            if action in ('stop','disconnect','connect','reset_defaults'):
                self.request_generation+=1
                if action in ('stop','disconnect'):self.auto_connect=False
                while True:
                    try:self.requests.get_nowait()
                    except queue.Empty:break
            data['_generation']=self.request_generation
            try:self.requests.put_nowait((action,data));return True
            except queue.Full:
                self.emit('error',text='待执行操作已满，本次点击未提交；请等待或点击停止');self.emit_flags();return False
    def reset(self,restore=True):
        self.combat.close();self.heroes.reset();self.ground_spawn_pending=None
        self.round_settings.clear()
        self.teleport_jobs.clear();self.teleport_active=None;self.cheats_applied=None
        self.features_applied.clear();self.features_round=None
        if self.b.player_queue:
            try:self.b.player_queue.close()
            except Exception as ex:self.emit('error',text='玩家操作已停止：'+str(ex))
            finally:self.b.player_queue=None
        self.chat=None;self.bio_pending=None;self.bot_stop_pending=None;errors=self.controls.stop(restore);self.emit('reset')
        if errors:self.emit('log',text='部分临时值尚未恢复，保持同一对局时将重试：'+errors[0])
    def advance_teleports(self):
        if self.heroes.pending:return
        if self.b.player_queue and self.b.player_queue.pending:
            try:
                if not self.b.player_queue.poll():return
                if self.teleport_active:self.emit('log',text='传送已由游戏处理：#'+str(self.teleport_active[1].index))
            except Exception as ex:
                if self.teleport_active:self.emit('error',text='传送 #'+str(self.teleport_active[1].index)+' 未完成：'+str(ex))
                else:self.emit('error',text='玩家操作未完成：'+str(ex))
            finally:
                if not self.b.player_queue.pending:self.teleport_active=None
            if self.b.player_queue.pending:return
        while self.teleport_jobs:
            operation,key,ordinal,epoch,context,generation=self.teleport_jobs.pop(0)
            if generation!=self.request_generation or epoch!=self.b.epoch or context!=self.b.context:
                self.emit('log',text='对局变化，已取消剩余批量传送');self.teleport_jobs.clear();return
            try:
                self.b.player_operation(operation,key,ordinal)
                self.teleport_active=(operation,key)
                self.emit('log',text='传送已入队：#'+str(key.index));return
            except (PlayerUnavailable,ValueError) as ex:
                self.emit('log',text='跳过玩家 #'+str(key.index)+'：'+str(ex))
            except Exception as ex:
                self.emit('error',text='传送玩家 #'+str(key.index)+' 失败：'+str(ex))
                if not self.b.mem or not self.b.mem.alive():self.teleport_jobs.clear();return
    def advance_each_round(self):
        if self.ground_spawn_pending:return
        if not self.each_round or self.auto_paused or time.monotonic()<self.cheats_next_at:return
        self.cheats_next_at=time.monotonic()+.4
        try:
            sample=self.b.round_sample();identity=sample[:3]
            if self.features_round!=identity:
                self.features_round=identity;self.features_applied.clear()
            if self.cheats_applied!=identity:
                if self.b.cheats_value()!=self.cheats_desired:
                    self.b.set_cheats(self.cheats_desired);self.cheats_next_at=time.monotonic()+1.
                else:
                    self.cheats_applied=identity
                    self.emit('log',text='房主本局 sv_cheats 已核对：'+str(int(self.cheats_desired)))
            for key in ('ammo','buy','scale'):
                if key in self.features_applied:continue
                value=self.feature_preferences.get(key)
                if value:
                    self.b.require(key)
                    if key=='scale':
                        value=model_scale_setting(value['head'],value['body'],value['uniform'],value['factor'])
                    setattr(self.controls,key,value)
                    self.emit('log',text='房主本局功能已应用：'+{'ammo':'无限子弹','buy':'随时购买枪械','scale':'模型尺寸'}[key])
                self.features_applied.add(key)
            self.cheats_auto_error=''
        except Exception as ex:
            if str(ex)!=self.cheats_auto_error:self.emit('log',text='每局应用等待房主对局：'+str(ex))
            self.cheats_auto_error=str(ex);self.cheats_next_at=time.monotonic()+1.5
    def start_ground_spawn(self,name):
        if self.ground_spawn_pending:raise NotReady('上一条刷枪请求正在等待游戏处理')
        command=self.b.prepare_weapon_spawn(name)
        self.ground_spawn_pending=dict(name=name,command=command,stage='prepare',epoch=self.b.epoch,
            context=self.b.context,generation=self.request_generation,deadline=time.monotonic()+8.)
        self.advance_ground_spawn()
    def advance_ground_spawn(self):
        job=self.ground_spawn_pending
        if job is None:return
        try:
            if self.quit.is_set() or job['generation']!=self.request_generation:
                self.ground_spawn_pending=None;return
            if not self.b.mem or job['epoch']!=self.b.epoch or job['context']!=self.b.current_context():
                raise NotReady('对局或连接已变化，已取消地面刷枪')
            if time.monotonic()>job['deadline']:raise NotReady('刷枪等待 sv_cheats=1 超时，未发送创建命令')
            self.b.prepare_weapon_spawn(job['name'])
            cheats=self.b.cheats_value()
            if job['stage']=='prepare' and not cheats:
                self.b.set_cheats(True);job['stage']='cheats'
                self.emit('log',text='刷枪正在开启 sv_cheats，读回生效后自动生成到地面');return
            if not cheats:return
            self.b.send(job['command']);self.ground_spawn_pending=None
            self.emit('log',text='已确认 sv_cheats=1，地面刷枪命令已提交：'+job['command']+'；落地结果以游戏为准')
        except Exception as ex:
            self.ground_spawn_pending=None;self.emit('error',text='地面刷枪未完成：'+str(ex))
    def start_bot_stop(self,value):
        self.b.prepare_bot_stop()
        pending=self.bot_stop_pending
        if pending and pending['epoch']==self.b.epoch and pending['context']==self.b.context and pending['generation']==self.request_generation:
            # Preserve command ordering when pause/resume are clicked in quick succession.
            pending['next_value' if pending['stage']=='result' else 'value']=value
            self.emit('log',text='已更新人机操作，等待当前指令处理后'+('暂停' if value else '恢复'));return
        self.bot_stop_pending=dict(value=value,stage='prepare',epoch=self.b.epoch,context=self.b.context,generation=self.request_generation,deadline=time.monotonic()+8.)
        self.advance_bot_stop()
    def advance_bot_stop(self):
        job=self.bot_stop_pending
        if job is None:return
        try:
            if self.quit.is_set() or job['generation']!=self.request_generation:
                self.bot_stop_pending=None;return
            if not self.b.mem or self.b.epoch!=job['epoch'] or self.b.current_context()!=job['context']:
                raise NotReady('对局或连接已变化，已取消人机暂停/恢复请求')
            self.b.prepare_bot_stop()
            if time.monotonic()>job['deadline']:
                detail='sv_cheats 未变为 1，未发送 bot_stop' if job['stage']=='cheats' else 'bot_stop 未变为目标值'
                raise NotReady('人机操作核对超时：'+detail)
            cheats=self.b.cheats_value()
            if job['stage']=='prepare' and not cheats:
                self.b.set_cheats(True);job['stage']='cheats'
                self.emit('log',text='正在开启 sv_cheats，确认生效后自动'+('暂停' if job['value'] else '恢复')+'人机');return
            if job['stage']=='cheats' and not cheats:return
            if job['stage'] in ('prepare','cheats'):
                self.b.send('bot_stop '+str(job['value']));job['stage']='result';job['deadline']=time.monotonic()+8.
                self.emit('log',text='已确认 sv_cheats=1，bot_stop '+str(job['value'])+' 已入队，等待读回结果');return
            if not cheats:raise NotReady('sv_cheats 已被关闭，人机操作未确认完成')
            if self.b.bot_stop_value()==job['value']:
                self.bot_stop_pending=None
                if job.get('next_value',job['value'])!=job['value']:
                    self.start_bot_stop(job['next_value']);return
                self.emit('log',text=('已暂停人机' if job['value'] else '已恢复人机')+'（已读回 bot_stop='+str(job['value'])+'）')
        except Exception as ex:
            self.bot_stop_pending=None;self.emit('error',text=str(ex))
    def close_connection(self):
        self.combat.close();self.heroes.close()
        try:self.b.close()
        except Exception as ex:self.emit('log',text='连接清理提示：'+str(ex))
    def advance_connection(self):
        """One discovery attempt per tick; retry forever without a sleeping attach loop."""
        generation=self.connection_generation
        cancelled=lambda:self.quit.is_set() or not self.auto_connect or generation!=self.request_generation
        if cancelled() or self.b.mem or time.monotonic()<self.next_connect:return
        self.emit('connection',connected=False,pending=True,requires_admin=False,text='正在自动发现游戏…')
        try:
            pid=self.b.connect(self.connection_game,cancelled=cancelled)
            if cancelled():self.close_connection();return
        except Exception as ex:
            self.close_connection()
            if cancelled():return
            self.next_connect=time.monotonic()+self.retry_interval
            code=getattr(ex,'code','connect_failed');detail=str(ex)
            phase={'not_running':'等待游戏启动','launcher_only':'等待启动器加载客户端','loading':'等待游戏模块加载'}.get(code,'连接暂未就绪')
            message=f'{phase} · {self.retry_interval:g} 秒后自动重试'
            self.emit('state',ready=False,text=message,players=[],epoch=self.b.epoch,capabilities={})
            self.emit('connection',connected=False,retrying=True,requires_admin=getattr(ex,'requires_admin',False),code=code,text=message)
            if detail!=self.connect_error:self.emit('log',text=message+'；'+detail)
            self.connect_error=detail;return
        self.connect_error='';self.tick_error='';self.last_ui=0.
        self.emit('connection',connected=True,requires_admin=False,text=f'已连接 PID {pid}')
        self.emit('log',text=f'版本校验通过，已连接 PID {pid}')
    def waiting_client_changed(self):
        """Rediscover only while waiting, at most once every three seconds."""
        now=time.monotonic()
        if not self.auto_connect or not self.b.mem or now<self.next_candidate_check:return False
        self.next_candidate_check=now+3.
        generation=self.request_generation
        cancelled=lambda:self.quit.is_set() or not self.auto_connect or generation!=self.request_generation
        try:
            pid,mods=discover_client(self.b.module_loader,self.connection_game,cancelled,
                probe=lambda item:self.b.probe_client(item,cancelled))
            return (not cancelled() and pid!=self.b.mem.pid
                    and self.b.probe_client((pid,mods),cancelled) is not None and not cancelled())
        except (NotReady,OSError,CompatibilityError):return False
    def execute(self,action,data):
        if data.get('_generation',self.request_generation)!=self.request_generation:return
        if action=='connect':
            self.auto_connect=True;self.auto_paused=False;self.connection_game=data.get('game')
            preferences=data.get('preferences')
            if preferences:
                self.each_round=preferences['enabled'];self.cheats_desired=preferences['cheats'];self.feature_preferences=preferences['features']
            self.connection_generation=self.request_generation;self.next_connect=0.;self.connect_error=''
            self.reset();self.players=[];self.last_context=None
            self.close_connection()
            self.emit('state',ready=False,text='正在查找并验证游戏…',players=[],capabilities={})
            return
        if action=='stop':
            self.auto_connect=False;self.auto_paused=True;self.reset()
            if not self.b.mem:self.emit('connection',connected=False,requires_admin=False,text='自动连接已暂停，点击连接游戏可恢复')
            self.emit('log',text='已停止持续功能、定时喊话与自动重连');return
        if action=='disconnect':
            self.auto_connect=False;self.auto_paused=True;self.reset();self.close_connection();self.players=[]
            self.emit('connection',connected=False,requires_admin=False,text='已断开，自动连接已暂停')
            self.emit('state',ready=False,text='已断开',players=[],capabilities={});return
        if action=='each_round':
            self.each_round=bool(data['enabled']);self.cheats_desired=bool(data['cheats']);self.cheats_applied=None;self.cheats_next_at=0.
            self.feature_preferences=data.get('features',{});self.features_applied.clear()
            if self.each_round:self.auto_paused=False
            self.emit('log',text='每局都应用：'+('开启' if self.each_round else '关闭'));return
        if action=='reset_defaults':
            self.connection_generation=self.request_generation
            self.each_round=False;self.feature_preferences={};self.cheats_desired=False
            self.reset();self.emit_flags();return
        if action=='heroes_model_watch':
            self.heroes.model_watch=bool(data['enabled']);self.heroes.next_model_sample=0.;return
        if not self.b.mem:raise NotReady('请先连接游戏')
        if data.get('epoch')!=self.b.epoch:raise NotReady('对局或连接已变化，本次操作未执行')
        if self.b.current_context()!=self.b.context:raise NotReady('对局已变化，本次操作未执行')
        feature={'cheats':'cheats','ammo':'ammo','buy':'buy','scale':'scale','ghost':'ghost','mutation_add':'mutation','mutation_read':'mutation_read','heroes':'heroes','heroes_temple':'heroes','heroes_auto':'heroes','heroes_no_wait':'heroes','heroes_upgrade':'heroes_upgrade','heroes_model':'heroes_model','heroes_custom_damage':'heroes_custom_damage','heroes_no_attack':'heroes_no_attack','weapon_spawn':'weapon_spawn','machine_scan':'machine','machine_reroll':'machine','chat':'chat','chat_timer':'chat'}.get(action)
        if feature and data.get('enabled',True):self.b.require(feature)
        if action=='locks':
            if data.get('invulnerable'):self.b.require('invulnerable')
            for key in ('hp','money'):
                if data.get(key+'_enabled'):self.b.require(key)
        if action=='once':self.b.require(data['field'])
        if action=='weapon_spawn':
            self.start_ground_spawn(data['weapon']);return
        if action=='heroes':
            self.heroes.native(data['operation'],data.get('wave'));return
        if action=='heroes_auto':
            self.heroes.configure_auto(bool(data['enabled']),data.get('seconds',3));return
        if action=='heroes_no_wait':
            self.heroes.configure_wait(bool(data['enabled']));return
        if action=='heroes_upgrade':
            self.heroes.upgrade_all(data['field'],data['level'],self.players);return
        if action=='heroes_custom_damage':
            self.combat.damage(bool(data['enabled']),data.get('value'));return
        if action=='heroes_no_attack':
            self.combat.protect(bool(data['enabled']),self.players);return
        if action=='heroes_model':
            self.heroes.select_models(data['path'],data.get('keys',[]),self.players);return
        if action=='heroes_temple':
            self.heroes.protect(bool(data['enabled']));return
        if action=='player_action':
            if data['operation'] in ('goto','bring'):
                keys=data.get('keys',[data.get('key')]);keys=[key for key in keys if key is not None]
                if not keys:raise ValueError('请先勾选玩家')
                if len(keys)>64:raise ValueError('单次传送目标过多')
                if data['operation']=='goto':keys=keys[:1]
                if len(self.teleport_jobs)+len(keys)>128:raise ValueError('批量传送队列已满，请等待完成后再试')
                self.teleport_jobs.extend((data['operation'],key,i,self.b.epoch,self.b.context,self.request_generation) for i,key in enumerate(keys))
                self.advance_teleports();return
            self.b.player_operation(data['operation'],data['key'])
            self.emit('log',text='操作已入队，等待游戏处理：'+data['operation']+' #'+str(data['key'].index));return
        if action=='invulnerability':
            self.controls.configure_invulnerability(data.get('keys',[]),data.get('auto',True))
            self.emit('invulnerability_targets',keys=self.controls.invulnerable_keys,auto=self.controls.invulnerable_auto)
            self.emit_flags();self.emit('log',text='已记住无敌对象 '+str(len(self.controls.invulnerable_keys))+' 人');return
        if action=='invulnerability_auto':
            self.controls.invulnerable_auto=bool(data['enabled'])
            self.emit('invulnerability_targets',keys=self.controls.invulnerable_keys,auto=self.controls.invulnerable_auto)
            self.emit('log',text='无敌模式每局自动应用：'+('开启' if self.controls.invulnerable_auto else '关闭'));return
        if action=='round_setting':
            field=data['field'];self.round_settings.configure(field,data.get('keys',[]),data.get('value'))
            if data.get('value') is not None:setattr(self.controls,field,None)
            self.emit_flags();self.emit('log',text='每局设置已更新：'+field);return
        if action=='command':
            target=bot_stop_target(data['text'])
            if target is not None:self.start_bot_stop(target);return
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
            hp_enabled=bool(data.get('hp_enabled'));money_enabled=bool(data.get('money_enabled'))
            invulnerable=bool(data.get('invulnerable',False))
            if (hp_enabled or money_enabled or invulnerable) and not keys:raise ValueError('请先勾选玩家')
            self.controls.configure_value_locks(keys,hp_enabled,money_enabled)
            if 'invulnerable' in data:
                self.controls.configure_invulnerability(keys if invulnerable else [],True)
            for field,enabled in (('hp',hp_enabled),('money',money_enabled)):
                if enabled:self.round_settings.configure(field,[],None)
            self.emit_flags();self.emit('log',text=f'玩家锁定已更新，目标 {len(self.controls.keys)} 人');return
        if action=='once':
            if not data['keys']:raise ValueError('请先勾选玩家')
            value=bounded_int(data['value'],1 if data['field']=='hp' else 0,999999,'数值')
            if data.get('lock'):
                self.controls.configure_value_locks(data['keys'],
                    data['field']=='hp' or self.controls.hp is not None,
                    data['field']=='money' or self.controls.money is not None)
                self.round_settings.configure(data['field'],[],None)
            done=skipped=0
            try:
                for key in data['keys']:
                    try:
                        if not can_set_player_values(self.b.validate(key,False)):
                            skipped+=1;continue
                        self.controls.apply_value(data['field'],key,value)
                    except PlayerUnavailable:
                        skipped+=1;continue
                    done+=1
            except Exception as ex:raise RuntimeError(f'已应用 {done} 人；后续停止：{ex}') from ex
            suffix=f'，已跳过 {skipped} 个死亡、观战、电视或已离开的目标' if skipped else ''
            self.emit('log',text=f'数值已写入 {done} 名存活玩家'+suffix);return
        if action=='ammo':
            self.controls.ammo=bool(data['enabled']);self.emit('log',text='全局弹药补满：'+('开启' if data['enabled'] else '关闭'));return
        if action=='ghost':
            count=self.controls.configure_ghost(data.get('keys',[]),bool(data['enabled']))
            self.emit_flags();self.emit('log',text=('幽灵显形' if data['enabled'] else '幽灵隐身：恢复原生规则')+' · '+str(count)+' 人');return
        if action=='cheats':
            enabled=data['enabled']
            self.cheats_desired=bool(enabled);self.cheats_applied=None
            if not enabled:self.bot_stop_pending=None;self.ground_spawn_pending=None
            self.b.set_cheats(enabled)
            base=_local_package_base();helper=base/'cheat_settings.py'
            if helper.is_file():
                import importlib.util
                spec=importlib.util.spec_from_file_location('cso2_host_cheat_settings',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
                try:module.save_enabled(enabled,expected_game=self.b.game)
                except Exception as ex:self.emit('error',text='游戏指令已入队，但本地服务器设置未同步：'+str(ex))
                else:self.emit('log',text='已同步本地服务器的作弊设置')
            self.emit('log',text='sv_cheats 设置已入队，状态以游戏实值为准');return
        if action=='buy':
            self.controls.buy=bool(data['enabled'])
            if not self.controls.buy:
                errors=self.controls.restore_buy()
                if errors:raise RuntimeError('购买锁定已停止，但临时标志尚未恢复：'+errors[0])
            self.emit('log',text='随时购买枪械（仅自己，含菜单 BUY TIME）：'+('开启，等待本地角色存活后应用' if data['enabled'] else '关闭并恢复'));return
        if action=='scale':
            scale=model_scale_setting(data.get('head'),data.get('body'),data.get('uniform',False),data.get('factor',1)) if data['enabled'] else None
            self.controls.scale=None;errors=self.controls.restore({0x37c,0x6ec,0x6f0})
            if errors:raise RuntimeError('比例锁定已停止，但部分模型尚未恢复：'+errors[0])
            self.controls.scale=scale
            detail=('整体 '+format(scale['factor'],'g')+' 倍' if scale['uniform'] else '头部 '+format(scale['head'],'g')+' / 身体 '+format(scale['body'],'g')) if scale else '已恢复'
            self.emit('log',text='模型尺寸：'+detail+('，等待游戏同步' if scale else ''));return
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
                self.advance_connection()
                if not self.b.mem:continue
                try:
                    players=self.b.snapshot()
                    if self.last_context is not None and self.last_context!=self.b.epoch:
                        self.reset(False);self.emit('log',text='对局或本地角色已变化，持续功能已停止，请重新勾选')
                    self.last_context=self.b.epoch;self.players=players
                    self.advance_each_round()
                    try:
                        for message in self.round_settings.step(players):self.emit('log',text=message)
                    except Exception as ex:
                        self.round_settings.clear();self.emit('error',text='每局设置已停止：'+str(ex));self.emit_flags()
                    self.controls.disable_unavailable()
                    for message in self.controls.step_isolated(players):self.emit('error',text=message);self.emit_flags()
                    restore_errors=self.controls.retry_restores()
                    restore_message=restore_errors[0] if restore_errors else ''
                    if restore_message and restore_message!=self.restore_error:self.emit('error',text='临时值仍待恢复，将继续重试：'+restore_message)
                    if not restore_message and self.restore_error:self.emit('log',text='待恢复的临时值已处理')
                    self.restore_error=restore_message
                    if self.b.queue:self.b.queue.poll()
                    self.combat.step(players)
                    self.heroes.step(players)
                    if self.b.player_queue or self.teleport_jobs:self.advance_teleports()
                    self.advance_bot_stop()
                    self.advance_ground_spawn()
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
                    if not stable or self.combat.no_attack or (self.combat.hook and self.combat.hook.desired is not None) or self.heroes.pending or self.heroes.protected or self.heroes.auto or self.heroes.no_wait or self.heroes.upgrades or self.ground_spawn_pending or self.teleport_jobs or self.teleport_active or self.chat or self.bot_stop_pending or self.controls.hp is not None or self.controls.money is not None or self.controls.ammo or self.controls.scale or self.controls.buy or self.controls.invulnerable or self.controls.ghost:self.reset(stable)
                    message=str(ex)
                    # A dead process or changed module set must not leave a stale
                    # handle behind. Release it here so the next automatic pass
                    # can discover a newly started client/PID.
                    connection_lost=False
                    try:
                        connection_lost=bool(self.b.mem and not self.b.mem.alive())
                    except Exception:
                        connection_lost=True
                    if isinstance(ex,(OSError,CompatibilityError)) or getattr(ex,'code',None)=='modules_changed':connection_lost=True
                    if not connection_lost and not stable and self.waiting_client_changed():connection_lost=True
                    if connection_lost:
                        self.reset(False)
                        self.close_connection();self.players=[];self.last_context=None;self.next_connect=0.
                        self.emit('connection',connected=False,retrying=self.auto_connect,requires_admin=False,code='process_lost',text='游戏连接已断开，正在重新发现…' if self.auto_connect else '游戏连接已断开，自动连接已暂停')
                    elif not stable:
                        self.b.invalidate()
                    if message!=self.tick_error:
                        self.emit('state',ready=False,text=message,players=[],epoch=self.b.epoch,capabilities={});self.tick_error=message
                    self.quit.wait(.3)
        finally:
            try:self.reset()
            finally:self.close_connection();self.emit('closed')






# BEGIN_UI_LANGUAGE
"""Window-local Chinese/English presentation; never rewrites command or entry values."""
import ctypes
import re
import tkinter as tk
from tkinter import ttk

EN = {
 '检查更新':'Check updates',
 '幽灵显形':'Reveal ghosts','幽灵隐身':'Restore ghost stealth',
 '显形':'Visible','隐身':'Hidden',
 '恢复默认值':'Restore defaults','撤销恢复默认值':'Undo restore defaults',
 '每局都应用':'Apply every round',
 '房主对局自动应用本页已保存的功能开关':'Apply saved feature switches in hosted matches',
 '前往当前玩家；传送过来可批量勾选':'Go to selected player; bring checked players',
 '已加入自定义；设置会自动保存。':'Added to custom commands; settings are saved automatically.',
 '购买与地面刷枪':'Buying / ground weapon spawn',
 '购买仅对自己生效：放开地点和本机菜单 BUY TIME；不跟随玩家勾选。':'Buying applies to you only: location and local menu BUY TIME. Player checkboxes do not apply.',
 '按自己的准星落点生成到地面；其他玩家可按游戏规则拾取，不发进背包。':'Spawn on the ground at your crosshair. Players may pick it up under game rules; not sent to inventory.',
 '默认分别缩放头部和身体；勾选整体缩放后使用整体倍率，独立输入保留。':'Scale head and body separately by default. Uniform mode uses its own factor and keeps both inputs.',
 '有限正数倍率；取消勾选大小缩放复选框后恢复原值。':'Positive finite factors. Uncheck Head / body size to restore the original values.',
 '整体等比例缩放':'Uniform model scale','整体倍率':'Scale factor','应用倍率':'Apply factor',
 '地面刷枪':'Spawn weapons on ground','生成到地面':'Spawn on ground',
 '瞄准地面生成武器，随后自行拾取。':'Aim at the ground to spawn a weapon, then pick it up.',
 '极端倍率可能出现模型或引擎异常；实际显示以游戏为准。':'Extreme factors may cause model or engine issues; check the in-game result.',
 '无敌模式':'Invulnerability','无敌模式运行中':'Invulnerability running','无敌':'Invulnerable',
 '点击应用并记住对象；重新勾选不改变名单。':'Apply and remember players; selection changes leave the list unchanged.',
 '选好对象后点击无敌模式应用。':'Select players, then click Invulnerability to apply.',
 '每局自动应用':'Apply every round',
 '解除已记住对象的无敌':'Remove remembered invulnerability',
 '已选模式 · 等待连接游戏':'Mode selected · waiting for game',
 '已选模式 · 等待勾选玩家':'Mode selected · waiting for checked players',
 '已选模式 · 等待玩家存活':'Mode selected · waiting for alive players',
 '等待游戏确认':'Waiting for game confirmation',
 '洛奇英雄传功能':'Heroes Mode','怪物直接死亡':'Kill current monsters','快速完成当前波':'Finish current wave',
 '神殿无法被攻击（不掉血）':'Protect temple (no damage)','直接到第':'Jump to wave','波攻击':'attack','跳转':'Jump',
 '仅本地房主的洛奇英雄传对局可用。':'Available in a local Heroes host match only.',
 '生化 ZETA · 变异技能':'Zombie ZETA · Mutations','仅生化 ZETA 模式可用。':'Available in Zombie ZETA only.',
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

# HEROES captions and diagnostics share the same window-local language switch.
EN.update({
 '怪物自动死亡':'Auto-kill monsters','停止怪物自动死亡':'Stop auto-kill',
 '神殿不掉血':'Protect temple','跳过准备 / 波间等待':'Skip preparation / wave breaks',
 '怪物死亡倒计时':'Auto-kill delay','输入后自动生效':'Changes apply automatically',
 '已自动应用':'Applied automatically','开启时生效':'Applies when enabled','请输入 0～3600 秒':'Enter 0–3600 seconds',
 '跳转攻击波次':'Jump to attack wave','波':'wave',
 '所有玩家攻击力':'All players: attack','所有玩家生命强化':'All players: health','应用全体':'Apply to all',
 '所有玩家自定义伤害':'All players: fixed damage','应用伤害':'Apply damage','启用自定义伤害':'Enable fixed damage',
 '怪物不攻击玩家':'Monsters ignore players','当前使用原生伤害':'Using normal damage',
 '玩家模型切换':'Player models','玩家 → 当前模型 → 下拉切换':'Player → Current model → Choose model',
 '清空':'Clear','打开后读取当前玩家模型。':'Open this window to read player models.',
 '选择模型…':'Choose model…','等待模型':'Waiting for model','待切换':'Pending',
 '下拉切换单人；下方 HERO 按钮应用于勾选玩家。':'Use a dropdown for one player, or a HERO button for checked players.',
 '等待参战玩家。':'Waiting for active players.','请先勾选要切换模型的玩家。':'Check players to change their models first.',
 '请先勾选要切换模型的玩家':'Check players to change their models first',
 '全体强化包含当前参战玩家；死亡玩家复活后补发。':'Upgrades apply to all active players, including dead players after they respawn.',
 '进入洛奇对局后读取强化等级。':'Join a Heroes match to load upgrade levels.',
 '已读取本局原生强化配置。':'Upgrade levels loaded for this match.','等待洛奇强化配置。':'Waiting for Heroes upgrade data.',
 '请先选择本局已加载的强化等级':'Select a loaded upgrade level first',
 '等待开始':'Waiting to start','准备':'Preparation','攻击':'Attack','结束':'Finished','本局结束':'Match finished',
 '等待攻击/执行结果':'waiting for attack / result',
 '上一项洛奇操作正在等游戏处理':'The previous Heroes action is still pending',
 '上一项游戏操作尚未结束':'The previous game action is still pending',
 '两项神殿伤害参数未在时限内达到目标值':'Temple damage settings were not confirmed before timeout',
 '人物模型原生路径版本不符：':'Player model code does not match this build: ',
 '伤害回调关闭：':'Damage callback shutdown: ','伤害回调未由游戏帧安装':'Damage callback was not installed on a game frame',
 '伤害回调清理：':'Damage callback cleanup: ','伤害安装队列已取消':'Damage installation queue was canceled',
 '伤害回调超过预留空间':'Damage callback exceeds reserved space',
 '原生怪物死亡流程已执行；后续怪物仍按本波配置出生':'Current monsters were killed; later spawns still follow this wave.',
 '另一房主工具正在使用自定义伤害':'Another host tool is using fixed damage',
 '地图没有加载该波次':'This wave is not loaded on the map','地图波次树正在变化':'Map wave data is changing',
 '地图波次表未加载或超出当前网络格式':'Map wave data is unavailable or exceeds the network format',
 '地图波次资源不连续或正在加载':'Map waves are incomplete or still loading','地图波次资源未确认':'Map wave resources are not verified',
 '对局已变化，洛奇操作取消':'Match changed; Heroes action canceled','对局正在切换':'The match is changing','对局已变化':'The match has changed',
 '已关闭':'Disabled','已开启':'Enabled','开启':'Enabled','关闭':'Disabled',
 '强化属性已读回':'Upgrade values confirmed','强化等级':'Upgrade level','自定义伤害':'Fixed damage','目标波次':'Target wave',
 '强化表查询接口不匹配':'Upgrade lookup interface does not match','强化调用已执行，但等级/实际属性未达到目标':'Upgrade ran, but the level or values do not match the request',
 '强化配置内容未确认':'Upgrade data is not verified','强化配置树正在变化':'Upgrade data is changing','强化配置表正在加载':'Upgrade table is loading',
 '当前对局没有该强化等级':'This upgrade level is unavailable in the current match','当前没有参战玩家':'No active players',
 '当前波已经进入结束阶段':'The current wave is already ending','怪物受击入口已变化':'Monster damage entry changed',
 '怪物受击入口由其他修改占用':'Another modification owns the monster damage entry',
 '怪物受击入口与此版本不匹配':'Monster damage entry does not match this build',
 '怪物受击路径与此版本不匹配':'Monster damage code does not match this build',
 '怪物目标筛选路径与此版本不匹配':'Monster targeting code does not match this build',
 '怪物目标标志尚待恢复：':'Monster target flags still need restoration: ',
 '所有玩家自定义伤害已启用：':'Fixed damage enabled for all players: ',
 '无法分配伤害回调':'Could not allocate the damage callback','未知强化类型':'Unknown upgrade type',
 '本局已结束，请等待下一局':'Match finished; wait for the next match','本局已结束':'Match finished',
 '本局强化配置表尚未加载':'Upgrade data has not loaded for this match','本波已进入结束/结算流程':'This wave is now ending / settling',
 '模型切换已确认':'Model change confirmed','模型加载接口尚未就绪':'Model loading interface is not ready',
 '模型已读回确认：#':'Model confirmed: #','模型引擎接口不匹配':'Model engine interface does not match',
 '模型接口方法发生变化':'Model interface method changed',
 '模型未达到目标：预缓存失败或原生角色规则覆盖了选择':'Model did not change: precaching failed or character rules overrode the selection',
 '模式事件系统尚未就绪':'Mode event system is not ready','此项仅适用于本地房主的洛奇英雄传模式':'Available only to the local host in Heroes mode',
 '死亡玩家将在复活后切换模型':'Dead players will change models after respawning',
 '洛奇伤害/停攻：':'Heroes damage / targeting: ','洛奇功能不可用原因：':'Heroes unavailable: ','洛奇功能暂不可用：':'Heroes temporarily unavailable: ',
 '自定义伤害：':'Fixed damage: ','怪物停攻：':'Monster targeting: ',
 '洛奇原生调用路径版本不符：':'Heroes code does not match this build: ',
 '洛奇操作已排入游戏主线程，等待执行结果':'Heroes action queued; waiting for the game frame',
 '洛奇操作未确认：':'Heroes action not confirmed: ','洛奇模式状态尚未就绪':'Heroes mode is not ready','洛奇波次正在切换':'Heroes wave is changing',
 '玩家刚刚死亡，复活后再强化':'Player died; upgrade after respawning','玩家刚刚离开参战阵营':'Player left the active team',
 '玩家属性虚函数不属于当前服务端':'Player attribute method does not belong to this server',
 '玩家已转为观战':'Player is now spectating','玩家强化原生路径版本不符：':'Player upgrade code does not match this build: ',
 '神殿伤害参数被外部更改，保护未保持，正在恢复原值':'Temple damage was changed externally; restoring original values',
 '神殿伤害变量不是数值':'Temple damage variable is not numeric','神殿伤害变量未注册':'Temple damage variable is not registered',
 '神殿伤害变量正在同步':'Temple damage variable is synchronizing','神殿伤害数值异常':'Invalid temple damage value','神殿伤害根变量未确认':'Temple damage root variable is not verified',
 '神殿保护切换尚未核对完成':'Temple protection change is still being verified',
 '神殿保护已关闭，两项伤害参数已恢复原值':'Temple protection disabled; both damage settings restored',
 '神殿保护已开启（普通怪与 Boss 伤害均已读回为 0）':'Temple protection enabled; normal and boss damage confirmed as zero',
 '等待原服务器模块恢复连接后还原神殿参数':'Waiting for the original server to restore temple settings',
 '关闭时未确认神殿参数恢复；原值：':'Temple restoration not confirmed at shutdown; original values: ',
 '等待时间已归零':'Wait time is now zero','等待时间未归零':'Wait time has not reached zero',
 '等待洛奇对局开始':'Waiting for a Heroes match','等待玩家复活':'Waiting for the player to respawn',
 '等待玩家存活后强化':'Waiting for the player to be alive before upgrading',
 '结束调用已执行，但尚未观察到本波结束':'Finish request ran, but this wave has not ended yet',
 '自定义伤害已关闭，恢复原生伤害':'Fixed damage disabled; normal damage restored',
 '该玩家的模型替换方法尚未确认':'Model replacement method is not verified for this player',
 '请选择列表中的 HERO 模型':'Choose a HERO model from the list',
 '跳波调用已执行，但未读回目标攻击阶段':'Wave jump ran, but the requested attack phase was not confirmed',
 '全体强化等待恢复：':'All-player upgrade waiting: ','神殿保护：':'Temple protection: ',
 '全体玩家强化':'All-player upgrades','跳过等待':'Skip waiting','神殿保护':'Temple protection',
})

def heroes_english(text):
    """Translate system-generated Heroes status fragments, never player names."""
    if text in EN:return EN[text]
    rules=(
        (r'等级 (\d+) · (.+) 倍',lambda m:f'Level {m[1]} · {m[2]}×'),
        (r'(\d+)（等级 (\d+)）',lambda m:f'{m[1]} (Level {m[2]})'),
        (r'第 (\d+) 波 · (.+) · 神殿生命 (\d+) · 本波剩余 (-?\d+)(.*)',lambda m:f'Wave {m[1]} · {heroes_english(m[2])} · Temple HP {m[3]} · Remaining {m[4]}'+heroes_english(m[5])),
        (r' · 自动清怪 (.*?)( · 等待强化 \d+ 人次)?',lambda m:' · Auto-kill '+heroes_english(m[1])+heroes_english(m[2] or '')),
        (r' · 等待强化 (\d+) 人次',lambda m:f' · Upgrades pending: {m[1]}'),
        (r'([\d.]+) 秒',lambda m:f'{m[1]} s'),
        (r'怪物自动死亡：开启，倒计时 (.+) 秒循环执行',lambda m:f'Auto-kill enabled: repeat every {m[1]} seconds'),
        (r'怪物自动死亡：关闭',lambda m:'Auto-kill disabled'),
        (r'跳过准备和波间等待：(开启|关闭)',lambda m:'Skip preparation and wave breaks: '+heroes_english(m[1])),
        (r'怪物不攻击玩家：(已开启|已关闭)',lambda m:'Monsters ignore players: '+heroes_english(m[1])),
        (r'已提交，实际单次伤害 (\d+)',lambda m:f'Submitted; effective damage per hit: {m[1]}'),
        (r'自定义伤害已提交，实际单次伤害值 (\d+)；等待游戏帧安装',lambda m:f'Fixed damage requested: {m[1]}; waiting for a game frame'),
        (r'已提交 (\d+) 人，等待游戏处理。',lambda m:f'Submitted for {m[1]} players; waiting for the game.'),
        (r'模型切换已排队：(.*)，共 (\d+) 人；死亡玩家复活后应用',lambda m:f'Model queued: {m[1]}, {m[2]} players; dead players apply after respawning'),
        (r'模型切换已排队：(\d+) 人；死亡玩家复活后应用',lambda m:f'Model change queued for {m[1]} players; dead players apply after respawning'),
        (r'全体玩家强化已排队：(atk|hp) 等级 (\d+)，共 (\d+) 人；死亡玩家复活后补发',lambda m:f'Upgrade queued: {"attack" if m[1]=="atk" else "health"} level {m[2]}, {m[3]} players; dead players apply after respawning'),
        (r'全体强化 (atk|hp) 完成：已确认 (\d+) 人，失败 (\d+) 人',lambda m:f'All-player {"attack" if m[1]=="atk" else "health"} upgrade: {m[2]} confirmed, {m[3]} failed'),
        (r'(模型切换|全体强化) #(\d+) (未执行|等待)：(.*)',lambda m:f'{"Model change" if m[1]=="模型切换" else "Upgrade"} #{m[2]} {"not applied" if m[3]=="未执行" else "waiting"}: '+heroes_english(m[4])),
        (r'已读回第 (\d+) 波攻击阶段',lambda m:f'Attack phase confirmed for wave {m[1]}'),
        (r'(自定义伤害|怪物死亡倒计时|目标波次|强化等级)(必须是整数|必须是数字)',lambda m:heroes_english(m[1])+(' must be an integer' if m[2]=='必须是整数' else ' must be numeric')),
        (r'(自定义伤害|怪物死亡倒计时|目标波次|强化等级)范围 (.+)',lambda m:heroes_english(m[1])+' range: '+m[2].replace('～','–')),
        (r'已提交：(.*)；等待游戏处理。',lambda m:'Submitted: '+heroes_english(m[1])+'; waiting for the game.'),
        (r'点击执行：(.*)',lambda m:'Run: '+heroes_english(m[1])),
    )
    for pattern,render in rules:
        match=re.fullmatch(pattern,text)
        if match:return render(match)
    for raw,en in sorted(EN.items(),key=lambda r:-len(r[0])):
        if len(raw)>=4 and text.startswith(raw):return en+heroes_english(text[len(raw):])
    return text


class UiLanguage:
    def __init__(self,root,language=None):
        self.root=root;self.lang=language or detect_language();self.widgets={};self.variables={};self.buttons=[]
        self.tabs=[];self.headings=[];self.combos=[];self.reverse={v:k for k,v in EN.items()};self.rendered={};self.callbacks=[]
        root.ui_language=self;self.title_source=root.title()
    def source(self,text):return self.rendered.get(str(text),self.reverse.get(str(text),str(text)))
    def t(self,text):
        raw=self.source(text)
        if self.lang=='zh':return raw
        hero_text=heroes_english(raw)
        translated=hero_text if hero_text!=raw else EN.get(raw)
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
        if widget in self.widgets or getattr(widget,'_ui_literal',False):return
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

# END_UI_LANGUAGE

# host_ui.py
"""Dark, portable CSO2 host tool. Build the entire window while withdrawn."""
import ctypes
import hashlib
import json
from pathlib import Path
import queue
import shutil
import sys
import time
import tkinter as tk
from tkinter import ttk, filedialog


BG='#10151d';SIDE='#131a24';CARD='#19222f';INPUT='#101923';BORDER='#293749'
TEXT='#e6edf6';MUTED='#8c9caf';ACCENT='#6ab7ff';BLUE='#225c91';GREEN='#69d6b3';RED='#ff9b9b'
TITLE='CSO2 Host Tool'
INVULNERABLE_HELP='彻底无法被击中，无法被伤害'

class AdminLaunchCancelled(OSError):pass

def relaunch_admin(path,game_directory='',connect=True):
    """Use the normal Windows UAC prompt, with no shell command interpolation."""
    import subprocess
    runtime=Path(sys.executable)
    if runtime.name.casefold()=='python.exe' and runtime.with_name('pythonw.exe').is_file():runtime=runtime.with_name('pythonw.exe')
    args=[str(Path(path).resolve()),'--elevated']
    if connect:args.append('--connect')
    if game_directory:args+=['--game-directory',str(game_directory)]
    shell=ctypes.WinDLL('shell32',use_last_error=True)
    shell.ShellExecuteW.argtypes=[ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_int]
    shell.ShellExecuteW.restype=ctypes.c_void_p
    ctypes.set_last_error(0)
    result=shell.ShellExecuteW(None,'runas',str(runtime),subprocess.list2cmdline(args),str(Path(path).resolve().parent),1)
    if not result or result<=32:
        if ctypes.get_last_error()==1223:raise AdminLaunchCancelled('已取消 Windows 管理员授权')
        raise OSError('无法以管理员身份启动房主工具（Windows 错误 '+str(ctypes.get_last_error() or result or 0)+'）')

def dark_titlebar(root):
    try:
        root.update_idletasks()
        u=ctypes.WinDLL('user32');u.GetParent.argtypes=[ctypes.c_void_p];u.GetParent.restype=ctypes.c_void_p
        hwnd=u.GetParent(root.winfo_id()) or root.winfo_id()
        dwm=ctypes.WinDLL('dwmapi');dwm.DwmSetWindowAttribute.argtypes=[ctypes.c_void_p,ctypes.c_uint,ctypes.c_void_p,ctypes.c_uint]
        for attr,value in ((20,1),(19,1),(35,0x1d1510),(36,0xf6ede6)):
            v=ctypes.c_int(value);dwm.DwmSetWindowAttribute(hwnd,attr,ctypes.byref(v),4)
    except (OSError,AttributeError):pass

def style_window(root):
    root.configure(bg=BG)
    root.option_add('*Font',('Microsoft YaHei UI',10))
    root.option_add('*Background',CARD);root.option_add('*Foreground',TEXT)
    root.option_add('*selectBackground',BLUE);root.option_add('*selectForeground',TEXT)
    root.option_add('*TCombobox*Listbox.background',INPUT)
    root.option_add('*TCombobox*Listbox.foreground',TEXT)
    root.option_add('*TCombobox*Listbox.selectBackground',BLUE)
    s=ttk.Style(root);s.theme_use('clam')
    s.configure('.',font=('Microsoft YaHei UI',10),background=CARD,foreground=TEXT)
    s.configure('TFrame',background=BG);s.configure('Card.TFrame',background=CARD)
    s.configure('TLabel',background=CARD,foreground=TEXT)
    s.configure('Muted.TLabel',foreground=MUTED)
    s.configure('TButton',background='#26384c',foreground=TEXT,borderwidth=0,padding=(11,6),relief='flat',focuscolor=ACCENT)
    s.map('TButton',background=[('disabled','#202a37'),('pressed','#20496f'),('active','#344f6b')],foreground=[('disabled','#657389')])
    s.configure('Accent.TButton',background=BLUE,foreground='#eff8ff')
    s.map('Accent.TButton',background=[('disabled','#202a37'),('pressed','#174a76'),('active','#2b73af')])
    s.configure('Small.TButton',padding=(10,5))
    s.configure('Undo.TButton',background='#d77720',foreground='#ffffff')
    s.map('Undo.TButton',background=[('pressed','#a95414'),('active','#ee9135')])
    s.configure('Running.TButton',background='#17644f',foreground='#e8fff5',padding=(11,6))
    s.map('Running.TButton',background=[('pressed','#124d3d'),('active','#217c63')])
    s.configure('TEntry',fieldbackground=INPUT,foreground=TEXT,insertcolor=TEXT,bordercolor=BORDER,lightcolor=BORDER,darkcolor=BORDER,padding=(7,5))
    s.configure('TCombobox',fieldbackground=INPUT,background='#283b50',foreground=TEXT,arrowcolor=ACCENT,bordercolor=BORDER,lightcolor=BORDER,darkcolor=BORDER,padding=(8,6),arrowsize=13)
    s.map('TCombobox',fieldbackground=[('readonly',INPUT)],foreground=[('readonly',TEXT)],selectbackground=[('readonly',INPUT)],selectforeground=[('readonly',TEXT)])
    s.configure('TCheckbutton',background=CARD,foreground=TEXT,padding=(2,6),focuscolor=CARD)
    s.map('TCheckbutton',background=[('active',CARD)],foreground=[('disabled','#627185'),('active','#ffffff')])
    s.configure('TRadiobutton',background=CARD,foreground=TEXT,indicatorbackground=INPUT,indicatorforeground=ACCENT,padding=4)
    s.map('TRadiobutton',background=[('active',CARD)])
    s.configure('Treeview',background=INPUT,fieldbackground=INPUT,foreground=TEXT,rowheight=30,borderwidth=0,font=('Microsoft YaHei UI',10))
    s.configure('Treeview.Heading',background='#233247',foreground='#aabfd6',font=('Microsoft YaHei UI',10),padding=(7,9),relief='flat')
    s.map('Treeview',background=[('selected','#264665')],foreground=[('selected','#ffffff')])
    s.map('Treeview.Heading',background=[('active','#2b415b')])
    s.configure('Vertical.TScrollbar',background='#3a5067',troughcolor=INPUT,borderwidth=0,arrowcolor=MUTED)
    s.configure('TNotebook',background=BG,borderwidth=0)
    s.configure('TNotebook.Tab',background=SIDE,foreground=MUTED,padding=(22,8),expand=(0,0,0,0),borderwidth=0,bordercolor=BORDER,lightcolor=BORDER,darkcolor=BORDER)
    # Clam supplies a smaller selected-tab padding unless its state map is cleared.
    s.map('TNotebook.Tab',padding=[],lightcolor=[],background=[('selected',CARD)],foreground=[('selected',ACCENT)])
    # Theme-independent dark checkbox artwork.
    off=tk.PhotoImage(master=root,width=20,height=20);on=tk.PhotoImage(master=root,width=20,height=20)
    off.put(BORDER,to=(1,1,18,18));off.put(INPUT,to=(2,2,17,17));on.put(BLUE,to=(1,1,18,18))
    for x,y in ((5,9),(6,10),(7,11),(8,12),(9,11),(10,10),(11,9),(12,8),(13,7),(14,6)):
        on.put('#e1f3ff',to=(x,y,x+2,y+2))
    root._checks=(off,on)
    s.element_create('HostCheck.indicator','image',off,('selected',on),width=25,sticky='w')
    s.layout('TCheckbutton',[('Checkbutton.padding',{'sticky':'nswe','children':[('HostCheck.indicator',{'side':'left','sticky':'w'}),('Checkbutton.label',{'side':'left','sticky':'nswe'})]})])

class ScrollFrame(tk.Frame):
    def __init__(self,parent,bg=BG):
        super().__init__(parent,bg=bg)
        self.canvas=tk.Canvas(self,bg=bg,bd=0,highlightthickness=0)
        bar=ttk.Scrollbar(self,orient='vertical',command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=bar.set)
        bar.pack(side='right',fill='y');self.canvas.pack(side='left',fill='both',expand=True)
        self.body=tk.Frame(self.canvas,bg=bg);self.window=self.canvas.create_window((0,0),window=self.body,anchor='nw')
        self.body.bind('<Configure>',lambda _:self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>',lambda e:self.canvas.itemconfigure(self.window,width=e.width))
        self.bind('<MouseWheel>',self.wheel);self.canvas.bind('<MouseWheel>',self.wheel)
    def wheel(self,event):
        if self.body.winfo_height()>self.canvas.winfo_height():self.canvas.yview_scroll(-int(event.delta/120),'units')
        return 'break'

def label(parent,text,muted=False,size=10,bg=CARD,**kw):
    return tk.Label(parent,text=text,bg=bg,fg=MUTED if muted else TEXT,font=('Microsoft YaHei UI',size),anchor='w',**kw)

class App:
    def __init__(self,root,path,settings=None,start_worker=True):
        self.root=root;root.withdraw();root.configure(bg=BG);self.updater=None
        self.path=Path(path);self.digest=hashlib.sha256(self.path.read_bytes()).hexdigest() if self.path.exists() else None
        self.log_path=self.path.with_suffix('.run.log');self.persist_logs=start_worker
        self.settings=settings or {};self.events=queue.Queue();self.worker=Worker(self.events,DATA['caps']) if start_worker else None
        self.save_job=None;self.save_dirty_at=None;self.settings_loading=True;self.undo_defaults=None;self.undo_runtime=None;self.saved_settings=None
        self.cheats_desired=bool(self.settings.get('cheats_desired',False))
        prefs=self.settings.get('feature_preferences',{})
        self.feature_preferences=dict(prefs) if isinstance(prefs,dict) else {}
        self.capabilities={};self.command_states={};self.feature_widgets=[];self.game_directory=self.settings.get('game_directory','')
        self.ready=False;self.epoch=-1;self.players={};self.checked=set();self.custom=[];self.pages={};self.nav={};self.closing=False;self.logs=[];self.last_cheats=False;self.needs_admin=False
        self.vars={};self.current_page='players';self.filter_job=None;self.state_epoch=None;self.invulnerable_targets=set();self.ghost_targets=set()
        self.auto_connect=bool(start_worker);self.fit_job=None;self.fitting_window=False
        root.title(TITLE);style_window(root);self.language=UiLanguage(root)
        width=min(880,max(760,root.winfo_screenwidth()-80));height=min(730,max(620,root.winfo_screenheight()-100))
        root.geometry(f'{width}x{height}+{max(0,(root.winfo_screenwidth()-width)//2)}+{max(0,(root.winfo_screenheight()-height)//2)}')
        root.minsize(min(800,width),min(620,height))
        self.build_shell();self.build_players();self.build_features();self.build_chat();self.build_commands();self.build_catalog()
        self.saved_settings=self.collect_settings();self.settings_loading=False;self.watch_settings()
        if self.worker:
            self.worker.each_round=self.vars['each_round'].get();self.worker.cheats_desired=self.cheats_desired
            self.worker.feature_preferences=dict(self.feature_preferences)
        self.apply_capabilities();self.show_page('players');root.protocol('WM_DELETE_WINDOW',self.close)
        self.language.capture(root);self.language.callbacks.append(self.refresh_language);self.language.refresh()
        root.bind('<Configure>',self.on_window_configure,add='+');self.queue_window_fit()
        root.report_callback_exception=self.callback_error
        root.bind('<Control-s>',lambda _:self.save());root.bind('<F8>',lambda _:self.stop())
        root.bind_all('<MouseWheel>',self.mousewheel,add='+')
        # Keep the native Listbox wheel bindings. A ComboboxListbox handler
        # returning 'break' runs first and would swallow scrolling entirely.
        root.bind_all('<ButtonPress-1>',self.background_click,add='+')
        if self.worker:self.worker.start();root.after(100,self.poll)
        self.log('启动完成，正在自动连接游戏。')
    def _combobox_popup_paths(self):
        """Return native popdown paths, including Tcl-only listbox children."""
        paths=[];pending=[self.root]
        while pending:
            widget=pending.pop();pending.extend(widget.children.values())
            if not isinstance(widget,ttk.Combobox):continue
            try:
                popup=str(self.root.tk.call('ttk::combobox::PopdownWindow',str(widget)))
                if self.root.tk.call('winfo','exists',popup):paths.append(popup)
            except tk.TclError:pass
        return paths
    def _is_combobox_popup_path(self,path):
        path=str(path or '')
        return any(path==popup or path.startswith(popup+'.') for popup in self._combobox_popup_paths())
    def _unpost_comboboxes(self):
        pending=[self.root]
        while pending:
            widget=pending.pop();pending.extend(widget.children.values())
            if not isinstance(widget,ttk.Combobox):continue
            try:
                popup=str(self.root.tk.call('ttk::combobox::PopdownWindow',str(widget)))
                if self.root.tk.call('winfo','exists',popup):
                    self.root.tk.call('ttk::combobox::Unpost',str(widget))
            except tk.TclError:pass
    def background_click(self,event):
        widget=event.widget
        try:
            path=str(widget)
            kind=self.root.tk.call('winfo','class',path)
            if kind=='ComboboxPopdown' or self._is_combobox_popup_path(path):
                # Popdown children exist only in Tcl, not Python's widget
                # registry. winfo_containing() can return None for an INSIDE
                # click; compare the raw Tcl path instead. Grab-routed outside
                # clicks still resolve to an outside path (or an empty one).
                containing_path=str(self.root.tk.call(
                    'winfo','containing',event.x_root,event.y_root))
                if containing_path and self._is_combobox_popup_path(containing_path):return
                self.release_edit_focus();return
            if isinstance(widget,str):
                try:widget=self.root.nametowidget(widget)
                except KeyError:return
            if widget.winfo_toplevel() is not self.root:return
            passive=widget.winfo_class() in ('Tk','Frame','TFrame','Labelframe','TLabelframe','Label','TLabel','Canvas')
            if isinstance(widget,ttk.Treeview):passive=not widget.identify_row(event.y)
            if passive:self.release_edit_focus()
        except (tk.TclError,KeyError,AttributeError):return
    def release_edit_focus(self):
        # Traverse Python widgets; explicitly unpost Tcl-only popdowns as well.
        pending=[self.root]
        while pending:
            widget=pending.pop();pending.extend(widget.children.values())
            try:
                if isinstance(widget,(tk.Entry,ttk.Entry,tk.Spinbox,ttk.Spinbox,ttk.Combobox)):
                    widget.selection_clear()
                elif isinstance(widget,tk.Text):widget.tag_remove('sel','1.0','end')
                if isinstance(widget,(ttk.Scale,ttk.Scrollbar)):widget.state(['!pressed','!active'])
            except tk.TclError:pass
        self._unpost_comboboxes()
        self.root.focus_set()
    def choose_game(self):
        selected=filedialog.askdirectory(title='选择目标游戏目录',initialdir=self.game_directory or str(Path.home()/'Desktop'))
        if selected:
            self.game_directory=selected;self.schedule_save();self.log('目标目录：'+selected)
            if self.auto_connect:self.request('connect',require_ready=False,game=selected)
    def connect_game(self):
        if not self.needs_admin:return self.request('connect',require_ready=False,game=self.game_directory)
        try:
            self.digest=portable_save(self.path,self.collect_settings(),self.digest)
            relaunch_admin(self.path,self.game_directory)
        except Exception as ex:self.log(str(ex),True);return False
        self.log('管理员窗口已启动，将自动重新连接游戏。');self.close();return True
    def feature_control(self,widget,key,command_text=None):
        self.feature_widgets.append((widget,key,command_text))
        widget.state(['disabled'])
        widget.bind('<Enter>',lambda _,w=widget:self.hint.configure(text=getattr(w,'unavailable_reason','') or '点击执行：'+str(w.cget('text')),fg=MUTED))
        return widget
    def apply_capabilities(self):
        live=[];watch=[]
        for widget,key,getter in self.feature_widgets:
            if not widget.winfo_exists():continue
            live.append((widget,key,getter));status=self.capabilities.get(key,{'available':False,'reason':'尚未连接并验证'})
            if getter:
                text=getter();watch.append(text)
                status=self.command_states.get(text,{'available':False,'reason':'等待验证当前指令'}) if status['available'] else status
            enabled=self.ready and status['available'];widget.state(['!disabled'] if enabled else ['disabled'])
            widget.unavailable_reason='' if enabled else str(widget.cget('text'))+'：'+status.get('reason','当前不可用')
        self.feature_widgets=live
        for key in ('hp','money','ammo','scale','buy','chat','invulnerable'):
            if not self.ready or not self.capabilities.get(key,{}).get('available',False):self.vars[key].set(False)
        if hasattr(self,'heroes_level_boxes'):
            enabled=self.ready and bool(self.heroes_level_rows) and self.capabilities.get('heroes_upgrade',{}).get('available',False)
            for box in self.heroes_level_boxes.values():box.state(['!disabled','readonly'] if enabled else ['disabled'])
        if hasattr(self,'heroes_model_widgets'):
            for widgets in self.heroes_model_widgets.values():widgets[-1].state(['!disabled','readonly'] if self.ready and self.capabilities.get('heroes_model',{}).get('available',False) else ['disabled'])
        if self.worker:self.worker.command_watch=list(dict.fromkeys(watch))
        if hasattr(self,'player_actions'):self.update_player_actions()
    def strvar(self,key,default):
        value=self.settings.get(key,default)
        var=tk.StringVar(value=str(value));self.vars[key]=var;return var
    def boolvar(self,key):
        var=tk.BooleanVar(value=False);self.vars[key]=var;return var
    def card(self,parent,title,subtitle=None):
        outer=tk.Frame(parent,bg=CARD,highlightbackground=BORDER,highlightthickness=1)
        outer.pack(fill='x',pady=(0,9))
        inside=tk.Frame(outer,bg=CARD);inside.pack(fill='both',expand=True,padx=12,pady=9)
        label(inside,title,size=11).pack(anchor='w',pady=(0,5))
        if subtitle:label(inside,subtitle,True,9,wraplength=730,justify='left').pack(anchor='w',pady=(0,4))
        return inside
    def build_shell(self):
        header=tk.Frame(self.root,bg=BG);header.pack(fill='x',padx=14,pady=(12,10))
        label(header,'CSO2 房主工具',size=15,bg=BG).pack(side='left')
        self.connect_button=ttk.Button(header,text='连接游戏',style='Accent.TButton',command=self.connect_game);self.connect_button.pack(side='right',padx=(7,0))
        ttk.Button(header,text='停止全部',command=self.stop).pack(side='right',padx=(7,0))
        self.defaults_button=ttk.Button(header,text='恢复默认值',command=self.restore_defaults);self.defaults_button.pack(side='right',padx=(7,0))
        self.language.button(header,style='Small.TButton').pack(side='right',padx=5)
        self.tabs=ttk.Notebook(self.root);self.tabs.pack(fill='both',expand=True,padx=12)
        for key,title in [('players','钱血'),('features','功能'),('chat','喊话'),('commands','指令')]:
            frame=tk.Frame(self.tabs,bg=BG,padx=10,pady=10);self.tabs.add(frame,text=title);self.pages[key]=frame
        self.tabs.bind('<<NotebookTabChanged>>',lambda _:self.remember_page())
        footer=tk.Frame(self.root,bg=BG);footer.pack(side='bottom',fill='x',padx=15,pady=(6,10),before=self.tabs)
        row=tk.Frame(footer,bg=BG);row.pack(fill='x')
        self.status=label(row,'○ 未连接游戏',True,9,bg=BG,wraplength=500,justify='left');self.status.pack(side='left')
        self.log_button=ttk.Button(row,text='展开日志',style='Small.TButton',command=self.toggle_log);self.log_button.pack(side='right')
        label(row,'F8 停止全部',True,9,bg=BG).pack(side='right',padx=12)
        self.update_button=ttk.Button(row,text='检查更新',style='Small.TButton',command=lambda:self.updater.check(manual=True) if self.updater else None);self.update_button.pack(side='right')
        label(row,'v'+APP_VERSION,True,9,bg=BG).pack(side='right',padx=8)
        self.hint=label(footer,'灰色按钮移上去可看原因。',True,9,bg=BG,wraplength=740,justify='left');self.hint.pack(fill='x',pady=(5,0))
        footer.bind('<Configure>',lambda e:self.hint.configure(wraplength=max(200,e.width)))
        self.log_frame=tk.Frame(footer,bg=BG)
        self.log_text=tk.Text(self.log_frame,height=5,bg=INPUT,fg=MUTED,font=('Microsoft YaHei UI',9),wrap='word',relief='flat',bd=0,state='disabled',highlightthickness=0,padx=8,pady=5)
        self.log_text.pack(fill='both',expand=True)
    def show_page(self,key):
        if key=='catalog':
            self.tabs.select(self.pages['commands']);self.command_tabs.select(self.pages['catalog'])
        else:self.tabs.select(self.pages[key])
        self.current_page=key
    def build_players(self):
        page=self.pages['players'];toolbar=tk.Frame(page,bg=BG);toolbar.pack(fill='x',pady=(0,7))
        self.selection_text=label(toolbar,'已勾选 0 人',True,9,bg=BG);self.selection_text.pack(side='left')
        for title,fn in [('取消勾选',lambda:self.select_all(False)),('全选',lambda:self.select_all(True))]:
            ttk.Button(toolbar,text=title,style='Small.TButton',command=fn).pack(side='right',padx=(6,0))
        table=tk.Frame(page,bg=INPUT);table.pack(fill='both',expand=True,pady=(0,9))
        columns=('check','index','name','hp','money','team','state')
        self.player_tree=ttk.Treeview(table,columns=columns,show='headings',selectmode='browse',height=7)
        for c,title,w in zip(columns,['选择','编号','昵称','血量','金钱','阵营','状态'],[48,48,180,95,100,65,128]):
            self.player_tree.heading(c,text=title);self.player_tree.column(c,width=w,minwidth=w if c!='name' else 100,anchor='w' if c=='name' else 'center',stretch=c=='name')
        bar=ttk.Scrollbar(table,orient='vertical',command=self.player_tree.yview);self.player_tree.configure(yscrollcommand=bar.set)
        bar.pack(side='right',fill='y');self.player_tree.pack(side='left',fill='both',expand=True)
        self.player_tree.bind('<ButtonRelease-1>',self.toggle_player);self.player_tree.bind('<space>',self.toggle_player)
        self.empty_label=label(table,'进入对局后显示玩家列表',True,bg=INPUT)
        self.empty_label.place(relx=.5,rely=.5,anchor='center')
        box=self.card(page,'修改所选玩家')
        box.master.pack_configure(side='bottom',before=table)
        self.player_editor=tk.Frame(box,bg=CARD);self.player_editor.pack(fill='x')
        values=self.player_values=tk.Frame(self.player_editor,bg=CARD);values.grid(row=0,column=0,sticky='nw')
        actions=self.player_action_panel=tk.Frame(self.player_editor,bg=CARD);actions.grid(row=0,column=1,sticky='nsew',padx=(16,0))
        self.player_editor.columnconfigure(1,weight=1)
        self.boolvar('invulnerable');self.boolvar('invulnerable_mode')
        invulnerability_row=tk.Frame(values,bg=CARD);invulnerability_row.pack(fill='x',pady=(0,7))
        self.invulnerable_button=ttk.Button(invulnerability_row,text='无敌模式',width=24,command=self.switch_invulnerability)
        self.invulnerable_button.grid(row=0,column=0,sticky='w')
        self.vars['invulnerable_auto']=tk.BooleanVar(value=bool(self.settings.get('invulnerable_auto',True)))
        self.invulnerable_menu=tk.Menu(self.root,tearoff=False,bg=CARD,fg=TEXT,activebackground=BLUE,activeforeground=TEXT)
        self.invulnerable_menu.add_checkbutton(label='每局自动应用',variable=self.vars['invulnerable_auto'],command=self.change_invulnerability_auto)
        self.invulnerable_menu.add_separator()
        self.invulnerable_menu.add_command(label='解除已记住对象的无敌',command=self.clear_invulnerability)
        self.invulnerable_arrow=ttk.Button(invulnerability_row,text='▾',width=2,style='Small.TButton',command=self.open_invulnerability_menu)
        self.invulnerable_arrow.grid(row=0,column=1,sticky='w',padx=(3,0))
        self.invulnerable_note=label(invulnerability_row,'点击应用并记住对象；重新勾选不改变名单。',True,9,wraplength=440,justify='left')
        self.invulnerable_note.grid(row=1,column=0,columnspan=2,sticky='w',pady=(3,0))
        self.invulnerable_tip=None;self.invulnerable_tip_job=None
        self.invulnerable_button.bind('<Enter>',lambda _:self.queue_invulnerability_tip(),add='+')
        self.invulnerable_button.bind('<Leave>',lambda _:self.hide_invulnerability_tip(),add='+')
        self.vars['invulnerable_mode'].trace_add('write',lambda *_:self.refresh_invulnerability_ui())
        self.player_tree.tag_configure('invulnerable',foreground=GREEN)
        label(actions,'前往当前玩家；传送过来可批量勾选',True,9).grid(row=0,column=0,columnspan=2,sticky='w',pady=(0,3))
        self.player_actions={}
        for i,(action,title) in enumerate((('vote','投票踢出'),('kick','无票踢出'),('goto','传送到此人身边'),('bring','将此人传送过来'),('copy','复制名字'),('ghost','幽灵显形'))):
            button=ttk.Button(actions,text=title,width=0,style='Small.TButton',command=lambda a=action:self.player_action(a))
            button.grid(row=1+i//2,column=i%2,columnspan=1,sticky='ew',padx=2,pady=2);self.player_actions[action]=button
        for col in range(2):actions.columnconfigure(col,weight=1)
        self.round_menus={};self.action_modes={};self.mode_checks={}
        for key,title,default in [('hp','血量',9999),('money','金钱',99999)]:
            row=tk.Frame(values,bg=CARD);row.pack(fill='x',pady=4)
            label(row,title,width=5).pack(side='left')
            ttk.Entry(row,textvariable=self.strvar(key+'_value',default),width=10).pack(side='left',padx=(5,10))
            self.feature_control(ttk.Button(row,text='设置'+title,style='Small.TButton',command=lambda k=key:self.apply_setting(k)),key).pack(side='left')
            menu=tk.Menu(self.root,tearoff=False,bg=CARD,fg=TEXT,activebackground=BLUE,activeforeground=TEXT)
            mode=self.settings.get(key+'_mode','once')
            self.action_modes[key]=mode if mode in ('once','round') else 'once'
            self.mode_checks[key]={value:tk.BooleanVar(value=self.action_modes[key]==value) for value in ('once','round')}
            self.boolvar('round_'+key)  # Active worker job, separate from the chosen UI mode.
            menu.add_checkbutton(label='立即设置',variable=self.mode_checks[key]['once'],command=lambda k=key:self.set_action_mode(k,'once'))
            menu.add_checkbutton(label='每局自动设置',variable=self.mode_checks[key]['round'],command=lambda k=key:self.set_action_mode(k,'round'))
            self.round_menus[key]=menu
            arrow=ttk.Button(row,text='▾',width=2,style='Small.TButton');arrow.pack(side='left',padx=(1,0))
            arrow.configure(command=lambda m=menu,w=arrow:self.open_action_menu(m,w))
            self.boolvar(key)  # Runtime acknowledgement stays separate from UI intent.
            ttk.Checkbutton(row,text='锁定所选玩家'+title,variable=self.boolvar(key+'_lock_mode'),command=lambda k=key:self.select_lock_mode(k)).pack(side='left',padx=(8,0))
        self.player_tree.bind('<<TreeviewSelect>>',lambda _:self.update_player_actions())
        self.update_player_actions()
    def open_action_menu(self,menu,widget):
        menu.entryconfigure(0,label=self.language.t('立即设置'));menu.entryconfigure(1,label=self.language.t('每局自动设置'))
        try:menu.tk_popup(widget.winfo_rootx(),widget.winfo_rooty()+widget.winfo_height())
        finally:menu.grab_release()
    def switch_invulnerability(self):
        # One explicit click snapshots the current objects. It is not a toggle.
        self.vars['invulnerable_mode'].set(True)
        return self.toggle_invulnerability()
    def open_invulnerability_menu(self):
        menu=self.invulnerable_menu;widget=self.invulnerable_arrow
        menu.entryconfigure(0,label=self.language.t('每局自动应用'))
        menu.entryconfigure(2,label=self.language.t('解除已记住对象的无敌'))
        try:menu.tk_popup(widget.winfo_rootx(),widget.winfo_rooty()+widget.winfo_height())
        finally:menu.grab_release()
    def change_invulnerability_auto(self):
        self.refresh_invulnerability_ui()
        if self.ready and self.invulnerable_targets:
            return self.request('invulnerability_auto',enabled=self.vars['invulnerable_auto'].get())
        return True
    def clear_invulnerability(self):
        if self.ready and (self.invulnerable_targets or self.vars['invulnerable'].get()):
            if not self.request('invulnerability',keys=[],auto=self.vars['invulnerable_auto'].get()):return False
        self.invulnerable_targets.clear();self.vars['invulnerable_mode'].set(False)
        self.refresh_invulnerability_ui();return True
    def refresh_invulnerability_ui(self):
        self.invulnerable_button.configure(text='无敌模式',style='TButton')
        remembered=self.invulnerable_targets;confirmed=0
        if not remembered:
            note='选好对象后点击无敌模式应用。' if self.vars['invulnerable_mode'].get() else '点击应用并记住对象；重新勾选不改变名单。'
        else:
            targets=[p for p in self.players.values() if p.key in remembered and p.alive]
            confirmed=sum(p.damage_mode==0 for p in targets)
            count=len(remembered);auto=self.vars['invulnerable_auto'].get()
            if self.language.lang=='zh':
                note=f'已记住 {count} 人 · '+('每局自动应用' if auto else '仅本次应用')
                note+=f' · 已确认 {confirmed}/{len(targets)} 人' if targets else ' · 等待对象存活'
            else:
                note=f'{count} remembered · '+('Apply every round' if auto else 'Apply once')
                note+=f' · Confirmed {confirmed}/{len(targets)}' if targets else ' · Waiting for players'
        self.invulnerable_note.configure(text=note,fg=GREEN if confirmed else MUTED)
    def on_window_configure(self,event):
        if event.widget is not self.root or self.fitting_window:return
        size=(event.width,event.height)
        if size!=getattr(self,'last_window_size',None):
            self.last_window_size=size;self.queue_window_fit()
    def queue_window_fit(self):
        if self.closing or self.fit_job is not None:return
        self.fit_job=self.root.after(100,self.fit_window)
    def window_work_area(self):
        # Use this window's monitor work area, excluding the taskbar.
        try:
            from ctypes import wintypes as wt
            class MonitorInfo(ctypes.Structure):
                _fields_=[('cbSize',wt.DWORD),('rcMonitor',wt.RECT),('rcWork',wt.RECT),('dwFlags',wt.DWORD)]
            user=ctypes.WinDLL('user32',use_last_error=True)
            user.MonitorFromWindow.argtypes=[wt.HWND,wt.DWORD];user.MonitorFromWindow.restype=wt.HANDLE
            user.GetMonitorInfoW.argtypes=[wt.HANDLE,ctypes.POINTER(MonitorInfo)];user.GetMonitorInfoW.restype=wt.BOOL
            info=MonitorInfo();info.cbSize=ctypes.sizeof(info)
            if user.GetMonitorInfoW(user.MonitorFromWindow(self.root.winfo_id(),2),ctypes.byref(info)):
                r=info.rcWork;return r.left,r.top,r.right,r.bottom
        except (OSError,AttributeError):pass
        return 0,0,self.root.winfo_screenwidth(),self.root.winfo_screenheight()
    def fit_window(self):
        self.fit_job=None
        if self.closing or self.fitting_window:return
        self.fitting_window=True
        try:
            root=self.root;root.update_idletasks()
            left,top,right,bottom=self.window_work_area()
            available_width=max(320,right-left-32);available_height=max(300,bottom-top-64)
            side_by_side=self.player_values.winfo_reqwidth()+self.player_action_panel.winfo_reqwidth()+80<=available_width
            if side_by_side:
                self.player_action_panel.grid_configure(row=0,column=1,sticky='nsew',padx=(16,0),pady=0)
            else:
                self.player_action_panel.grid_configure(row=1,column=0,columnspan=2,sticky='ew',padx=0,pady=(12,0))
            if side_by_side:self.player_action_panel.grid_configure(columnspan=1)
            root.update_idletasks()
            needed_width=min(available_width,root.winfo_reqwidth()+8)
            needed_height=min(available_height,root.winfo_reqheight()+8)
            root.minsize(needed_width,needed_height)
            if root.state()=='zoomed':return
            width=min(available_width,max(needed_width,root.winfo_width()))
            height=min(available_height,max(needed_height,root.winfo_height()))
            # Content fitting may resize, but never repositions a user-dragged window.
            if (width,height)!=(root.winfo_width(),root.winfo_height()):
                root.geometry(f'{width}x{height}')
        finally:self.fitting_window=False
    def queue_invulnerability_tip(self):
        self.hide_invulnerability_tip()
        self.hint.configure(text=INVULNERABLE_HELP,fg=ACCENT)
        self.invulnerable_tip_job=self.root.after(350,self.show_invulnerability_tip)
    def show_invulnerability_tip(self):
        self.invulnerable_tip_job=None
        if self.closing:return
        tip=tk.Toplevel(self.root);tip.withdraw();tip.overrideredirect(True);tip.attributes('-topmost',True)
        tip.configure(bg=BORDER);self.invulnerable_tip=tip
        tk.Label(tip,text=INVULNERABLE_HELP,bg=CARD,fg=TEXT,font=('Microsoft YaHei UI',10),padx=12,pady=8).pack(padx=1,pady=1)
        tip.update_idletasks();x=min(self.root.winfo_pointerx()+14,tip.winfo_screenwidth()-tip.winfo_reqwidth()-8)
        y=min(self.root.winfo_pointery()+18,tip.winfo_screenheight()-tip.winfo_reqheight()-8)
        tip.geometry(f'+{max(0,x)}+{max(0,y)}');tip.deiconify()
    def hide_invulnerability_tip(self):
        if self.invulnerable_tip_job is not None:
            self.root.after_cancel(self.invulnerable_tip_job);self.invulnerable_tip_job=None
        if self.invulnerable_tip is not None:self.invulnerable_tip.destroy();self.invulnerable_tip=None
    def toggle_invulnerability(self):
        targets=self.setting_targets()
        if not targets or not self.ready:
            self.log('无敌模式已选定；选好对象后点击按钮应用。');self.refresh_invulnerability_ui();return True
        accepted=self.request('invulnerability',keys=targets,auto=self.vars['invulnerable_auto'].get())
        if accepted:
            self.invulnerable_targets=set(targets)
            self.refresh_invulnerability_ui()
        return accepted
    def select_lock_mode(self,key):
        if not self.ready or not self.checked:
            if self.ready and not self.vars[key+'_lock_mode'].get():return self.update_locks(use_highlight=False)
            self.log(('血量' if key=='hp' else '金钱')+'模式已保留，勾选玩家后生效。');return True
        return self.update_locks(use_highlight=False)
    def set_action_mode(self,key,mode):
        if mode not in ('once','round'):raise ValueError('未知设置模式')
        self.action_modes[key]=mode
        self.schedule_save()
        for value,var in self.mode_checks[key].items():var.set(value==mode)
        if not self.settings_loading and mode=='once' and self.ready and self.vars['round_'+key].get():
            self.request('round_setting',field=key,keys=[],value=None)
    def setting_targets(self):
        valid={player.key for player in self.players.values()}
        self.checked.intersection_update(valid)
        if not self.checked:
            player=self.active_player()
            if player is not None:self.checked.add(player.key)
        self.draw_selection()
        return sorted(self.checked,key=lambda item:item.index)
    def apply_setting(self,key):
        if self.vars[key+'_lock_mode'].get():return self.apply_once(key)
        return self.set_each_round(key) if self.action_modes[key]=='round' else self.apply_once(key)
    def set_each_round(self,key):
        targets=self.setting_targets()
        if not targets or not self.ready:
            self.log(('血量' if key=='hp' else '金钱')+'设置已保留；选好玩家后点击设置。');return True
        return self.request('round_setting',field=key,keys=targets,value=self.vars[key+'_value'].get())
    def active_player(self):
        selected=self.player_tree.selection()
        return self.players.get(selected[0]) if len(selected)==1 else None
    def ghost_action_targets(self):
        if not self.ready or not self.capabilities.get('ghost',{}).get('available',False):return []
        player=self.active_player()
        targets=[p for p in self.players.values() if p.key in self.checked] if self.checked else ([player] if player else [])
        return [p for p in targets if p.alive and p.team==2 and
                re.sub(r'[\s_\-]+','',p.name).casefold() not in ('cso2tv','sourcetv','hltv')]
    def update_player_actions(self):
        player=self.active_player()
        for action,button in self.player_actions.items():
            if action=='ghost':
                targets=self.ghost_action_targets()
                hiding=bool(targets) and all(p.key in self.ghost_targets for p in targets)
                # The action shows the acknowledged persistent override; the
                # roster separately shows actual sampled render alpha.
                button.configure(text=self.language.t('幽灵隐身' if hiding else '幽灵显形'))
                button.state(['!disabled'] if targets else ['disabled'])
                continue
            enabled=player is not None and (action=='copy' or (self.ready and not player.local and player.team in (2,3)))
            if action in ('goto','bring'):
                targets=[p for p in self.players.values() if p.key in self.checked] if self.checked else ([player] if player else [])
                if action=='goto' and player:targets=[player]+targets
                enabled=self.ready and any(not p.local and p.team in (2,3) and
                    re.sub(r'[\s_\-]+','',p.name).casefold() not in ('cso2tv','sourcetv','hltv') for p in targets)
            button.state(['!disabled'] if enabled else ['disabled'])
    def player_action(self,action):
        if action=='ghost':
            targets=self.ghost_action_targets()
            if not targets:self.log('请选择存活的 T 阵营幽灵',True);return False
            enabled=not all(p.key in self.ghost_targets for p in targets)
            return self.request('ghost',keys=[p.key for p in targets],enabled=enabled)
        if action in ('goto','bring'):
            keys=sorted(self.checked,key=lambda k:k.index)
            if not keys:
                selected=self.active_player()
                keys=[selected.key] if selected else []
            if action=='goto':
                eligible={p.key for p in self.players.values() if not p.local and p.team in (2,3)
                          and re.sub(r'[\s_\-]+','',p.name).casefold() not in ('cso2tv','sourcetv','hltv')}
                keys=[key for key in keys if key in eligible]
                selected=self.active_player()
                keys=[selected.key] if selected and selected.key in eligible else keys[:1]
            if not keys:self.log('请先勾选玩家',True);return False
            return self.request('player_action',operation=action,keys=keys)
        player=self.active_player()
        if player is None:self.log('请先点选一名玩家',True);return False
        if action=='copy':
            self.root.clipboard_clear();self.root.clipboard_append(player.name);self.log('已复制名字：'+player.name);return True
        if player.local:self.log('不能对自己执行此操作',True);return False
        if player.team not in (2,3):self.log('观战或电视实体不能作为此操作目标',True);return False
        return self.request('player_action',operation=action,key=player.key)
    def refresh_language(self):
        self.heroes_model_window.title(self.language.t('玩家模型切换'))
        self.update_heroes_models(self.heroes_model_rows,self.heroes_model_reason)
        self.update_heroes_levels(self.heroes_level_rows,self.language.source(self.heroes_upgrade_status.cget('text')))
        self.update_players(list(self.players.values()));self.filter_catalog();self.queue_window_fit()
        self.defaults_button.configure(text=self.language.t('撤销恢复默认值' if self.undo_defaults is not None else '恢复默认值'))
    def toggle_player(self,event):
        if event.keysym=='space':iid=self.player_tree.focus()
        else:
            if self.player_tree.identify_column(event.x)!='#1':return
            iid=self.player_tree.identify_row(event.y)
        if iid not in self.players:return
        key=self.players[iid].key
        if key in self.checked:self.checked.remove(key)
        else:self.checked.add(key)
        self.draw_selection()
        if any(self.vars[name].get() for name in ('hp','money','hp_lock_mode','money_lock_mode')):
            if not self.checked:
                for name in ('hp','money'):self.vars[name].set(False)
            self.update_locks(use_highlight=False)
    def select_all(self,enabled):
        self.checked={p.key for p in self.players.values()} if enabled else set()
        # Checking rows and highlighting an action target are separate Tk states.
        # Choose one visible target only when there is no existing selection;
        # Go-to uses one highlighted destination; bring consumes checked identities.
        if enabled and self.active_player() is None:
            rows=[iid for iid in self.player_tree.get_children() if iid in self.players]
            eligible=[iid for iid in rows if not self.players[iid].local and self.players[iid].team in (2,3)]
            candidates=eligible or rows
            if candidates:
                iid=candidates[0]
                self.player_tree.selection_set(iid);self.player_tree.focus(iid);self.player_tree.see(iid)
        self.draw_selection()
        if any(self.vars[name].get() for name in ('hp','money','hp_lock_mode','money_lock_mode')):
            if not self.checked:self.vars['hp'].set(False);self.vars['money'].set(False)
            self.update_locks(use_highlight=False)
    def draw_selection(self):
        self.selection_text.configure(text=f'已勾选 {len(self.checked)} 人')
        for iid,p in self.players.items():self.player_tree.set(iid,'check','☑' if p.key in self.checked else '☐')
        self.refresh_invulnerability_ui()
        self.update_player_actions()
    def apply_once(self,key):
        targets=self.setting_targets()
        if not targets or not self.ready:
            self.log(('血量' if key=='hp' else '金钱')+'设置已保留；选好玩家后点击设置。');return True
        return self.request('once',keys=targets,field=key,value=self.vars[key+'_value'].get(),lock=self.vars[key+'_lock_mode'].get())
    def update_locks(self,use_highlight=True):
        targets=self.setting_targets() if use_highlight else sorted(self.checked,key=lambda item:item.index)
        if not self.ready:return False
        if not targets:
            self.log('已清空锁定对象；勾选玩家时锁定其当前数值。')
        accepted=self.request('locks',keys=targets,
                              hp_enabled=bool(targets) and self.vars['hp_lock_mode'].get(),
                              money_enabled=bool(targets) and self.vars['money_lock_mode'].get())
        if not accepted:self.vars['hp'].set(False);self.vars['money'].set(False)
        return accepted
    def build_features(self):
        scroll=ScrollFrame(self.pages['features']);scroll.pack(fill='both',expand=True);page=scroll.body
        top=tk.Frame(page,bg=CARD,highlightbackground=BORDER,highlightthickness=1);top.pack(fill='x',pady=(0,9))
        self.boolvar('each_round');self.vars['each_round'].set(bool(self.settings.get('each_round',False)))
        ttk.Checkbutton(top,text='每局都应用',variable=self.vars['each_round'],command=lambda:self.change_each_round(capture=True)).pack(anchor='w',padx=11)
        row=tk.Frame(top,bg=CARD);row.pack(fill='x')
        self.feature_control(ttk.Checkbutton(row,text='开启作弊功能（sv_cheats）',variable=self.boolvar('cheats'),command=self.change_cheats),'cheats').pack(side='left',padx=11,pady=6)
        self.vars['cheats'].set(self.cheats_desired)
        label(row,'状态以游戏实值为准',True,9).pack(side='right',padx=12)
        label(top,'房主对局自动应用本页已保存的功能开关',True,9).pack(anchor='w',padx=12,pady=(0,6))
        box=self.card(page,'对所有人有效')
        self.feature_control(ttk.Checkbutton(box,text='无限子弹',variable=self.boolvar('ammo'),command=lambda:self.request('ammo',enabled=self.vars['ammo'].get())),'ammo').pack(anchor='w')
        row=tk.Frame(box,bg=CARD);row.pack(fill='x',pady=(2,0))
        self.feature_control(ttk.Checkbutton(row,text='头部 / 身体大小',variable=self.boolvar('scale'),command=self.apply_scale),'scale').pack(side='left')
        label(row,'头部').pack(side='left',padx=(12,5))
        self.head_scale_entry=ttk.Entry(row,textvariable=self.strvar('head',1),width=9);self.head_scale_entry.pack(side='left')
        label(row,'身体').pack(side='left',padx=(12,5))
        self.body_scale_entry=ttk.Entry(row,textvariable=self.strvar('body',1),width=9);self.body_scale_entry.pack(side='left')
        self.feature_control(ttk.Button(row,text='应用比例',style='Small.TButton',command=self.apply_scale),'scale').pack(side='left',padx=12)
        row=tk.Frame(box,bg=CARD);row.pack(fill='x',pady=(4,0))
        self.boolvar('scale_uniform');self.vars['scale_uniform'].set(bool(self.settings.get('scale_uniform',False)))
        self.uniform_scale_check=ttk.Checkbutton(row,text='整体等比例缩放',variable=self.vars['scale_uniform'],command=self.change_scale_mode)
        self.uniform_scale_check.pack(side='left')
        label(row,'整体倍率').pack(side='left',padx=(12,5))
        self.uniform_scale_entry=ttk.Entry(row,textvariable=self.strvar('model_scale',1),width=9);self.uniform_scale_entry.pack(side='left')
        self.update_scale_inputs()
        label(box,'默认分别缩放头部和身体；勾选整体缩放后使用整体倍率，独立输入保留。',True,9,wraplength=720,justify='left').pack(anchor='w',pady=(4,0))
        label(box,'有限正数倍率；取消勾选大小缩放复选框后恢复原值。',True,9,wraplength=720,justify='left').pack(anchor='w')
        label(box,'极端倍率可能出现模型或引擎异常；实际显示以游戏为准。',True,9,wraplength=720,justify='left').pack(anchor='w')
        box=self.card(page,'购买与地面刷枪');self.weapon_tools_card=box
        self.buy_check=self.feature_control(ttk.Checkbutton(box,text='随时购买枪械',variable=self.boolvar('buy'),command=lambda:self.request('buy',enabled=self.vars['buy'].get())),'buy');self.buy_check.pack(anchor='w')
        label(box,'购买仅对自己生效：放开地点和本机菜单 BUY TIME；不跟随玩家勾选。',True,9,wraplength=730,justify='left').pack(anchor='w',pady=(2,6))
        label(box,'地面刷枪',size=10).pack(anchor='w',pady=(3,1))
        label(box,'按自己的准星落点生成到地面；其他玩家可按游戏规则拾取，不发进背包。',True,9,wraplength=730,justify='left').pack(anchor='w')
        row=tk.Frame(box,bg=CARD);row.pack(fill='x',pady=(5,0))
        label(row,'武器').pack(side='left',padx=(0,9))
        self.weapon_query=tk.StringVar();ttk.Entry(row,textvariable=self.weapon_query,width=12).pack(side='left',padx=(0,8))
        self.weapon_choice=tk.StringVar();self.weapon_box=ttk.Combobox(row,textvariable=self.weapon_choice,state='readonly',width=26);self.weapon_box.pack(side='left',fill='x',expand=True)
        self.spawn_weapon_button=self.feature_control(ttk.Button(row,text='生成到地面',style='Small.TButton',command=self.spawn_weapon),'weapon_spawn');self.spawn_weapon_button.pack(side='left',padx=(9,0))
        self.weapon_query.trace_add('write',lambda *_:self.filter_weapons());self.filter_weapons()
        box=self.card(page,'生化 ZETA · 变异技能')
        row=tk.Frame(box,bg=CARD);row.pack(fill='x',pady=(0,5))
        label(row,'增加变异次数').pack(side='left');ttk.Entry(row,textvariable=self.strvar('mutation_count',1),width=5).pack(side='left',padx=9)
        self.feature_control(ttk.Button(row,text='增加',style='Small.TButton',command=lambda:self.request('mutation_add',count=self.vars['mutation_count'].get())),'mutation').pack(side='left')
        self.feature_control(ttk.Button(row,text='读取次数',style='Small.TButton',command=lambda:self.request('mutation_read')),'mutation_read').pack(side='left',padx=8)
        label(row,'单次 1～10',True,9).pack(side='left')
        row=tk.Frame(box,bg=CARD);row.pack(fill='x',pady=4)
        self.machine_rows=[];self.machine_choice=tk.StringVar();self.machine_box=ttk.Combobox(row,textvariable=self.machine_choice,state='readonly',width=28);self.machine_box.pack(side='left',fill='x',expand=True)
        self.feature_control(ttk.Button(row,text='刷新机器',style='Small.TButton',command=lambda:self.request('machine_scan')),'machine').pack(side='left',padx=8)
        self.feature_control(ttk.Button(row,text='重抽机器技能',style='Small.TButton',command=self.reroll_machine),'machine').pack(side='left')
        self.bio_status=label(box,'仅生化 ZETA 模式可用。',True,9,wraplength=720,justify='left');self.bio_status.pack(anchor='w',pady=(4,0))
        box=self.card(page,'洛奇英雄传功能');self.heroes_card=box
        bar=tk.Frame(box,bg=CARD);bar.pack(fill='x',pady=(0,6))
        self.boolvar('heroes_auto');self.boolvar('heroes_no_wait')
        self.heroes_auto_button=self.feature_control(ttk.Button(bar,text='怪物自动死亡',style='Small.TButton',command=self.toggle_heroes_auto),'heroes')
        self.heroes_auto_button.pack(side='left')
        self.vars['heroes_auto'].trace_add('write',lambda *_:self.refresh_heroes_auto())
        self.feature_control(ttk.Button(bar,text='快速完成当前波',style='Small.TButton',command=lambda:self.request('heroes',operation='finish')),'heroes').pack(side='left',padx=8)
        options=tk.Frame(box,bg=CARD);options.pack(fill='x',pady=(0,4))
        self.feature_control(ttk.Checkbutton(options,text='神殿不掉血',variable=self.boolvar('heroes_temple'),command=lambda:self.request('heroes_temple',enabled=self.vars['heroes_temple'].get())),'heroes').pack(side='left')
        self.feature_control(ttk.Checkbutton(options,text='跳过准备 / 波间等待',variable=self.vars['heroes_no_wait'],command=lambda:self.request('heroes_no_wait',enabled=self.vars['heroes_no_wait'].get())),'heroes').pack(side='left',padx=20)
        form=tk.Frame(box,bg=CARD);form.pack(anchor='w',fill='x',pady=(3,6));self.heroes_form=form
        form.columnconfigure(0,minsize=170);form.columnconfigure(1,minsize=260)
        label(form,'怪物死亡倒计时',True).grid(row=0,column=0,sticky='w',pady=5)
        interval=tk.Frame(form,bg=CARD);interval.grid(row=0,column=1,sticky='w',pady=5)
        self.heroes_interval_entry=ttk.Entry(interval,textvariable=self.strvar('heroes_seconds',3),width=8,justify='center')
        self.heroes_interval_entry.pack(side='left');label(interval,'秒',True).pack(side='left',padx=8)
        self.heroes_interval_hint=label(form,'输入后自动生效',True,9);self.heroes_interval_hint.grid(row=0,column=2,sticky='w',padx=(12,0))
        self.heroes_seconds_job=None
        self.vars['heroes_seconds'].trace_add('write',lambda *_:self.queue_heroes_seconds())
        self.heroes_interval_entry.bind('<Return>',lambda _:self.commit_heroes_seconds())
        self.heroes_interval_entry.bind('<FocusOut>',lambda _:self.commit_heroes_seconds())
        label(form,'跳转攻击波次',True).grid(row=1,column=0,sticky='w',pady=5)
        wave=tk.Frame(form,bg=CARD);wave.grid(row=1,column=1,sticky='w',pady=5)
        ttk.Entry(wave,textvariable=self.strvar('heroes_wave',1),width=8,justify='center').pack(side='left');label(wave,'波',True).pack(side='left',padx=8)
        self.feature_control(ttk.Button(form,text='跳转',width=12,style='Small.TButton',command=lambda:self.request('heroes',operation='jump',wave=self.vars['heroes_wave'].get())),'heroes').grid(row=1,column=2,sticky='ew',padx=(12,0),pady=5)
        self.heroes_level_rows=[];self.heroes_level_boxes={}
        for row,(field,title) in enumerate((('atk','所有玩家攻击力'),('hp','所有玩家生命强化')),2):
            label(form,title,True).grid(row=row,column=0,sticky='w',pady=5)
            combo=ttk.Combobox(form,textvariable=self.strvar('heroes_'+field,''),state='readonly',width=23)
            combo.grid(row=row,column=1,sticky='ew',pady=5);self.heroes_level_boxes[field]=combo
            self.feature_control(ttk.Button(form,text='应用全体',width=12,style='Small.TButton',command=lambda f=field:self.apply_heroes_upgrade(f)),'heroes_upgrade').grid(row=row,column=2,sticky='ew',padx=(12,0),pady=5)
        label(form,'所有玩家自定义伤害',True).grid(row=4,column=0,sticky='w',pady=5)
        self.heroes_damage_entry=ttk.Entry(form,textvariable=self.strvar('heroes_damage_value','999999999'),width=23)
        self.heroes_damage_entry.grid(row=4,column=1,sticky='ew',pady=5)
        self.feature_control(ttk.Button(form,text='应用伤害',width=12,style='Small.TButton',command=lambda:self.apply_heroes_damage(True)),'heroes_custom_damage').grid(row=4,column=2,sticky='ew',padx=(12,0),pady=5)
        self.heroes_damage_switch=self.feature_control(ttk.Checkbutton(form,text='启用自定义伤害',variable=self.boolvar('heroes_custom_damage'),command=lambda:self.apply_heroes_damage(self.vars['heroes_custom_damage'].get())),'heroes_custom_damage')
        self.heroes_damage_switch.grid(row=5,column=0,sticky='w',pady=5)
        self.heroes_no_attack_switch=self.feature_control(ttk.Checkbutton(form,text='怪物不攻击玩家',variable=self.boolvar('heroes_no_attack'),command=lambda:self.request('heroes_no_attack',enabled=self.vars['heroes_no_attack'].get())),'heroes_no_attack')
        self.heroes_no_attack_switch.grid(row=5,column=1,columnspan=2,sticky='w',pady=5)
        self.heroes_damage_note=label(form,'当前使用原生伤害',True,9)
        self.heroes_damage_note.grid(row=6,column=0,columnspan=3,sticky='w',pady=(0,5))
        self.heroes_model_rows=[];self.heroes_model_reason=''
        self.heroes_model_open=False;self.heroes_model_widgets={};self.heroes_model_choices={};self.heroes_model_checks={}
        self.heroes_model_button=self.feature_control(ttk.Button(box,text='玩家模型切换',style='Small.TButton',command=self.toggle_heroes_models),'heroes_model')
        self.heroes_model_button.pack(anchor='w',pady=(5,6))
        self.heroes_model_window=tk.Toplevel(self.root);self.heroes_model_window.withdraw();self.heroes_model_window.title('玩家模型切换')
        self.heroes_model_window.configure(bg=BG);self.heroes_model_window.geometry('880x510');self.heroes_model_window.minsize(700,380)
        self.heroes_model_window.transient(self.root);self.heroes_model_window.protocol('WM_DELETE_WINDOW',self.close_heroes_models)
        self.heroes_model_panel=tk.Frame(self.heroes_model_window,bg=INPUT,padx=16,pady=14);self.heroes_model_panel.pack(fill='both',expand=True)
        top=tk.Frame(self.heroes_model_panel,bg=INPUT);top.pack(fill='x')
        label(top,'玩家 → 当前模型 → 下拉切换',True,9,bg=INPUT).pack(side='left')
        ttk.Button(top,text='全选',style='Small.TButton',command=lambda:self.check_all_heroes_models(True)).pack(side='right')
        ttk.Button(top,text='清空',style='Small.TButton',command=lambda:self.check_all_heroes_models(False)).pack(side='right',padx=6)
        model_scroll=ScrollFrame(self.heroes_model_panel,bg=CARD);model_scroll.pack(fill='both',expand=True,pady=12)
        self.heroes_model_list=model_scroll.body
        self.heroes_model_note=label(self.heroes_model_panel,'打开后读取当前玩家模型。',True,9,bg=INPUT,wraplength=740);self.heroes_model_note.pack(anchor='w',pady=(0,6))
        buttons=tk.Frame(self.heroes_model_panel,bg=INPUT);buttons.pack(fill='x')
        self.heroes_model_presets=[]
        for i,(name,path) in enumerate(HERO_MODELS):
            button=self.feature_control(ttk.Button(buttons,text=name,width=13,style='Small.TButton',command=lambda p=path:self.apply_heroes_model(p)),'heroes_model')
            button.grid(row=i//4,column=i%4,sticky='ew',padx=(0,7),pady=4);self.heroes_model_presets.append(button)
        label(box,'全体强化包含当前参战玩家；死亡玩家复活后补发。',True,9).pack(anchor='w',pady=(4,0))
        self.heroes_upgrade_status=label(box,'进入洛奇对局后读取强化等级。',True,9,wraplength=740);self.heroes_upgrade_status.pack(anchor='w')
        self.heroes_status=label(box,'仅本地房主的洛奇英雄传对局可用。',True,9,wraplength=740,justify='left');self.heroes_status.pack(anchor='w',pady=(4,0))

    def apply_heroes_damage(self,enabled):
        value=self.vars['heroes_damage_value'].get()
        if enabled:
            try:stored=heroes_fixed_damage(value)
            except ValueError as ex:self.log(str(ex),True);self.vars['heroes_custom_damage'].set(False);return False
        accepted=self.request('heroes_custom_damage',enabled=enabled,value=value)
        if accepted:
            self.heroes_damage_note.configure(text=f'已提交，实际单次伤害 {stored:.0f}' if enabled else '当前使用原生伤害')
            self.schedule_save()
        return accepted

    def refresh_heroes_auto(self):
        enabled=self.vars['heroes_auto'].get()
        self.heroes_auto_button.configure(text='停止怪物自动死亡' if enabled else '怪物自动死亡',style='Running.TButton' if enabled else 'Small.TButton')
    def toggle_heroes_auto(self):
        enabled=not self.vars['heroes_auto'].get()
        if self.request('heroes_auto',enabled=enabled,seconds=self.vars['heroes_seconds'].get()):self.vars['heroes_auto'].set(enabled)
    def apply_heroes_seconds(self):
        try:bounded_float(self.vars['heroes_seconds'].get(),0,3600,'怪物死亡倒计时')
        except ValueError as ex:self.log(str(ex),True);return False
        if self.vars['heroes_auto'].get():return self.request('heroes_auto',enabled=True,seconds=self.vars['heroes_seconds'].get())
        self.schedule_save();return True
    def queue_heroes_seconds(self):
        if self.settings_loading or self.closing:return
        if self.heroes_seconds_job is not None:self.root.after_cancel(self.heroes_seconds_job)
        self.heroes_seconds_job=self.root.after(500,self.commit_heroes_seconds)
    def commit_heroes_seconds(self):
        if self.heroes_seconds_job is not None:self.root.after_cancel(self.heroes_seconds_job);self.heroes_seconds_job=None
        if self.settings_loading or self.closing:return
        try:seconds=bounded_float(self.vars['heroes_seconds'].get(),0,3600,'怪物死亡倒计时')
        except ValueError:self.heroes_interval_hint.configure(text='请输入 0～3600 秒');return False
        stamp=(seconds,bool(self.vars['heroes_auto'].get()))
        if stamp==getattr(self,'heroes_seconds_applied',None):return True
        accepted=self.apply_heroes_seconds()
        if accepted:self.heroes_seconds_applied=stamp;self.heroes_interval_hint.configure(text='已自动应用' if stamp[1] else '开启时生效')
        return accepted
    def toggle_heroes_models(self):
        self.heroes_model_open=True
        window=self.heroes_model_window;self.root.update_idletasks();window.update_idletasks()
        left,top,right,bottom=self.window_work_area()
        width=min(max(880,window.winfo_width(),window.winfo_reqwidth()),right-left-32)
        height=min(max(510,window.winfo_height()),bottom-top-64)
        window.minsize(min(700,width),min(380,height))
        x=self.root.winfo_rootx()+(self.root.winfo_width()-width)//2
        y=self.root.winfo_rooty()+(self.root.winfo_height()-height)//2
        x=max(left,min(x,right-width-16));y=max(top,min(y,bottom-height-48))
        # A leading '+' also preserves negative absolute coordinates on left monitors.
        window.geometry(f'{width}x{height}+{x}+{y}');window.deiconify();window.lift()
        if self.worker:self.worker.submit('heroes_model_watch',enabled=True)
    def close_heroes_models(self):
        self.heroes_model_open=False;self.heroes_model_window.withdraw()
        if self.worker:self.worker.submit('heroes_model_watch',enabled=False)
    def check_all_heroes_models(self,enabled):
        for var in self.heroes_model_checks.values():var.set(enabled)
    def update_heroes_models(self,rows,reason=''):
        self.heroes_model_rows=rows;self.heroes_model_reason=reason
        players={p.key:p for p in self.players.values()}
        rows=[row for row in rows if row['key'] in players]
        keys={r['key'] for r in rows}
        for key in list(self.heroes_model_widgets):
            if key not in keys:
                for widget in self.heroes_model_widgets.pop(key):widget.destroy()
                self.heroes_model_checks.pop(key,None);self.heroes_model_choices.pop(key,None)
        names={path:name for name,path in HERO_MODELS}
        for rownum,row in enumerate(rows):
            key=row['key'];p=players[key]
            if key not in self.heroes_model_widgets:
                checked=tk.BooleanVar(value=False);choice=tk.StringVar(value=self.language.t('选择模型…'))
                check=ttk.Checkbutton(self.heroes_model_list,variable=checked)
                who=label(self.heroes_model_list,'',size=9);who._ui_literal=True
                current=label(self.heroes_model_list,'',True,9)
                combo=ttk.Combobox(self.heroes_model_list,textvariable=choice,values=[name for name,_ in HERO_MODELS],state='readonly',width=15)
                combo.bind('<<ComboboxSelected>>',lambda _,k=key:self.choose_heroes_model(k))
                self.heroes_model_widgets[key]=(check,who,current,combo);self.heroes_model_checks[key]=checked;self.heroes_model_choices[key]=choice
            check,who,current,combo=self.heroes_model_widgets[key]
            who.configure(text=f'#{key.index} {p.name[:18]}'+(' · '+self.language.t('自己') if p.local else '')+(' · '+self.language.t('死亡') if not row['alive'] else ''))
            model_name=names.get(row['path']) or (Path(row['path']).stem if row['path'] else '等待模型')
            current.configure(text=self.language.t(model_name)+(' · '+self.language.t('待切换') if row['pending'] else ''))
            if combo.current()<0:self.heroes_model_choices[key].set(self.language.t('选择模型…'))
            for col,widget in enumerate((check,who,current,combo)):widget.grid(row=rownum,column=col,sticky='w',padx=(0,12),pady=5)
            combo.state(['!disabled','readonly'] if self.ready and self.capabilities.get('heroes_model',{}).get('available',False) else ['disabled'])
        self.heroes_model_note.configure(text=reason or ('下拉切换单人；下方 HERO 按钮应用于勾选玩家。' if rows else '等待参战玩家。'))
        self.language.capture(self.heroes_model_list)
    def choose_heroes_model(self,key):
        selected=self.heroes_model_choices[key].get();path=dict(HERO_MODELS).get(selected)
        if path:self.apply_heroes_model(path,[key])
    def apply_heroes_model(self,path,keys=None):
        if keys is None:keys=[key for key,var in self.heroes_model_checks.items() if var.get()]
        if not keys:self.heroes_model_note.configure(text='请先勾选要切换模型的玩家。');return False
        if self.request('heroes_model',path=path,keys=keys):
            self.heroes_model_note.configure(text=f'已提交 {len(keys)} 人，等待游戏处理。');return True
        return False

    def update_heroes_levels(self,rows,reason=''):
        self.heroes_level_rows=rows
        for field,box in self.heroes_level_boxes.items():
            selected=box.current();raw=self.language.source(self.vars['heroes_'+field].get())
            sources=[f'等级 {level} · {atk:g} 倍' if field=='atk' else f'{hp}（等级 {level}）' for level,atk,hp in rows]
            if raw in sources:selected=sources.index(raw)
            values=[self.language.t(value) for value in sources];box.configure(values=values)
            if values:box.current(selected if 0<=selected<len(values) else 0)
        self.heroes_upgrade_status.configure(text=reason or ('已读取本局原生强化配置。' if rows else '等待洛奇强化配置。'))
    def apply_heroes_upgrade(self,field):
        index=self.heroes_level_boxes[field].current()
        if not 0<=index<len(self.heroes_level_rows):self.log('请先选择本局已加载的强化等级',True);return False
        return self.request('heroes_upgrade',field=field,level=self.heroes_level_rows[index][0])
    def update_scale_inputs(self):
        uniform=self.vars['scale_uniform'].get()
        for entry in (self.head_scale_entry,self.body_scale_entry):entry.state(['disabled'] if uniform else ['!disabled'])
        self.uniform_scale_entry.state(['!disabled'] if uniform else ['disabled'])
    def change_scale_mode(self):
        self.update_scale_inputs()
        if self.ready and self.vars['scale'].get():return self.apply_scale()
        return True
    def change_each_round(self,capture=False):
        if capture and self.ready and self.vars['each_round'].get():
            self.cheats_desired=bool(self.vars['cheats'].get())
            self.feature_preferences.update(ammo=bool(self.vars['ammo'].get()),buy=bool(self.vars['buy'].get()))
            self.feature_preferences['scale']=dict(head=self.vars['head'].get(),body=self.vars['body'].get(),uniform=self.vars['scale_uniform'].get(),factor=self.vars['model_scale'].get()) if self.vars['scale'].get() else False
        self.schedule_save()
        if self.worker:self.worker.submit('each_round',enabled=self.vars['each_round'].get(),cheats=self.cheats_desired,features=dict(self.feature_preferences))
    def change_cheats(self):
        desired=bool(self.vars['cheats'].get())
        if self.request('cheats',enabled=desired):
            self.cheats_desired=desired;self.schedule_save()
    def apply_scale(self):
        return self.request('scale',enabled=self.vars['scale'].get(),head=self.vars['head'].get(),body=self.vars['body'].get(),uniform=self.vars['scale_uniform'].get(),factor=self.vars['model_scale'].get())
    def filter_weapons(self):
        text=self.weapon_query.get().lower().strip()
        self.weapon_rows=[w for w in DATA['weapons'] if text in (w['name']+' '+w.get('title','')+' '+w['category']).lower()]
        self.weapon_box.configure(values=[w.get('title') or w['name'] for w in self.weapon_rows])
        if self.weapon_rows:self.weapon_box.current(0)
        else:self.weapon_choice.set('')
    def spawn_weapon(self):
        command=self.weapon_command()
        if command:self.request('weapon_spawn',weapon=self.weapon_rows[self.weapon_box.current()]['name'])
        else:self.log('请先选择武器',True)
    def reroll_machine(self):
        index=self.machine_box.current()
        if not 0<=index<len(self.machine_rows):self.log('请先刷新并选择一台变异机器',True);return
        self.request('machine_reroll',key=self.machine_rows[index].key)
    def build_chat(self):
        box=self.card(self.pages['chat'],'游戏内喊话')
        self.chat_text=tk.Text(box,height=10,bg=INPUT,fg=TEXT,insertbackground=TEXT,relief='flat',wrap='word',padx=10,pady=9,highlightthickness=1,highlightbackground=BORDER,font=('Microsoft YaHei UI',11))
        self.chat_text.pack(fill='x',pady=(3,12));self.chat_text.insert('1.0',str(self.settings.get('chat_text','')))
        row=tk.Frame(box,bg=CARD);row.pack(fill='x')
        self.chat_team=self.strvar('chat_team','all')
        ttk.Radiobutton(row,text='全体',value='all',variable=self.chat_team).pack(side='left')
        ttk.Radiobutton(row,text='团队',value='team',variable=self.chat_team).pack(side='left',padx=(8,22))
        label(row,'间隔').pack(side='left');ttk.Entry(row,textvariable=self.strvar('interval',10),width=6).pack(side='left',padx=7);label(row,'秒').pack(side='left')
        row=tk.Frame(box,bg=CARD);row.pack(fill='x',pady=(15,0))
        self.feature_control(ttk.Button(row,text='立即发言',style='Accent.TButton',command=self.send_chat),'chat').pack(side='left')
        self.feature_control(ttk.Checkbutton(row,text='定时发言',variable=self.boolvar('chat'),command=self.timer_chat),'chat').pack(side='left',padx=18)
        label(box,'只发到当前对局；退出对局自动停止。',True,9).pack(anchor='w',pady=(12,0))
    def send_chat(self):self.request('chat',text=self.chat_text.get('1.0','end-1c'),team=self.chat_team.get()=='team')
    def timer_chat(self):self.request('chat_timer',enabled=self.vars['chat'].get(),text=self.chat_text.get('1.0','end-1c'),team=self.chat_team.get()=='team',interval=self.vars['interval'].get())
    def build_commands(self):
        page=self.pages['commands'];self.command_tabs=ttk.Notebook(page);self.command_tabs.pack(fill='both',expand=True)
        quick=ScrollFrame(self.command_tabs);custom=ScrollFrame(self.command_tabs)
        catalog=tk.Frame(self.command_tabs,bg=BG,padx=7,pady=8);self.pages['catalog']=catalog
        self.command_tabs.add(quick,text='默认');self.command_tabs.add(custom,text='自定义');self.command_tabs.add(catalog,text='更多命令')
        box=self.card(quick.body,'人机操作')
        row=tk.Frame(box,bg=CARD);row.pack(fill='x',pady=(0,7))
        label(row,'人机数量').pack(side='left');ttk.Entry(row,textvariable=self.strvar('bot_count',10),width=6).pack(side='left',padx=8)
        self.feature_control(ttk.Button(row,text='设置数量',style='Small.TButton',command=self.set_bot_count),'commands',lambda:'bot_quota_mode normal; bot_quota '+self.vars['bot_count'].get()).pack(side='left')
        label(row,'难度').pack(side='left',padx=(20,7))
        self.difficulty=ttk.Combobox(row,state='readonly',width=10,values=['0 简单','1 普通偏易','2 普通','3 较难','4 困难','5 很难','6 专家','7 精英']);self.difficulty.current(7);self.difficulty.pack(side='left')
        difficulty=self.settings.get('difficulty',7)
        if type(difficulty) is int and 0<=difficulty<=7:self.difficulty.current(difficulty)
        self.difficulty.bind('<<ComboboxSelected>>',self.schedule_save,add='+')
        self.feature_control(ttk.Button(row,text='设置难度',style='Small.TButton',command=lambda:self.send_command('bot_difficulty '+str(self.difficulty.current()))),'commands',lambda:'bot_difficulty '+str(self.difficulty.current())).pack(side='left',padx=8)
        grid=tk.Frame(box,bg=CARD);grid.pack(fill='x')
        actions=[('加一人机','bot_add'),('删除人机','bot_kick'),('处死人机','bot_kill'),('刷新游戏','mp_restartgame 1'),('加入 T 人机','bot_add_t'),('加入 CT 人机','bot_add_ct'),('暂停人机','bot_stop 1'),('恢复人机','bot_stop 0')]
        for i,(title,command) in enumerate(actions):
            self.feature_control(ttk.Button(grid,text=title,style='Accent.TButton',command=lambda c=command:self.send_command(c)),'commands',lambda c=command:c).grid(row=i//4,column=i%4,sticky='ew',padx=4,pady=5)
        for col in range(4):grid.columnconfigure(col,weight=1,uniform='actions')
        box=self.card(quick.body,'常用指令')
        actions=[('进入观战','jointeam 1'),('开启队友伤害','mp_friendlyfire 1'),('关闭队友伤害','mp_friendlyfire 0'),('BOT 语音关闭','bot_chatter off'),('人机只用刀','bot_knives_only'),('恢复所有武器','bot_all_weapons')]
        for i,(title,command) in enumerate(actions):
            if i%3==0:row=tk.Frame(box,bg=CARD);row.pack(fill='x',pady=4)
            self.feature_control(ttk.Button(row,text=title,style='Small.TButton',command=lambda c=command:self.send_command(c)),'commands',lambda c=command:c).pack(side='left',fill='x',expand=True,padx=4)
        self.custom_body=custom.body
        toolbar=tk.Frame(custom.body,bg=BG);toolbar.pack(fill='x',pady=(7,6))
        label(toolbar,'说明',True,9,bg=BG,width=17).pack(side='left',padx=(8,0));label(toolbar,'指令',True,9,bg=BG).pack(side='left')
        ttk.Button(toolbar,text='＋ 新增',style='Small.TButton',command=lambda:self.add_custom('新指令','')).pack(side='right',padx=7)
        self.custom_rows=tk.Frame(custom.body,bg=BG);self.custom_rows.pack(fill='x')
        entries=self.settings.get('custom',DATA['custom'])
        if not isinstance(entries,list):entries=DATA['custom']
        for entry in entries[:200]:
            if isinstance(entry,(list,tuple)) and len(entry)==2:self.add_custom(str(entry[0]),str(entry[1]))
        row=tk.Frame(page,bg=CARD,padx=9,pady=8);row.pack(side='bottom',fill='x',pady=(8,0),before=self.command_tabs)
        label(row,'临时指令').pack(side='left',padx=(0,8));self.manual_command=tk.StringVar()
        entry=ttk.Entry(row,textvariable=self.manual_command);entry.pack(side='left',fill='x',expand=True)
        entry.bind('<Return>',lambda _:self.send_command(self.manual_command.get()))
        self.feature_control(ttk.Button(row,text='发送',style='Accent.TButton',command=lambda:self.send_command(self.manual_command.get())),'commands',lambda:self.manual_command.get()).pack(side='left',padx=7)
        ttk.Button(row,text='存为自定义',style='Small.TButton',command=self.store_manual).pack(side='left')
    def set_bot_count(self):
        try:value=bounded_int(self.vars['bot_count'].get(),0,64,'BOT 数量')
        except ValueError as ex:self.log(str(ex),True);return
        self.send_command(f'bot_quota_mode normal; bot_quota {value}')
    def add_custom(self,title,command):
        frame=tk.Frame(self.custom_rows,bg=CARD,highlightbackground=BORDER,highlightthickness=1);frame.pack(fill='x',pady=(0,5))
        name=tk.StringVar(value=title);value=tk.StringVar(value=command);item=(frame,name,value);self.custom.append(item)
        ttk.Entry(frame,textvariable=name,width=13).pack(side='left',padx=(7,8),pady=6)
        ttk.Entry(frame,textvariable=value).pack(side='left',fill='x',expand=True,pady=6)
        self.feature_control(ttk.Button(frame,text='发送',style='Accent.TButton',command=lambda:self.send_command(value.get())),'commands',lambda v=value:v.get()).pack(side='left',padx=7)
        ttk.Button(frame,text='×',width=2,style='Small.TButton',command=lambda:self.delete_custom(item)).pack(side='left',padx=(0,7))
        if self.language.widgets:self.language.capture(frame)
        for var in (name,value):self.watch_setting(var)
        self.schedule_save()
    def delete_custom(self,item):
        self.custom.remove(item);item[0].destroy();self.schedule_save()
    def build_catalog(self):
        page=self.pages['catalog'];line=tk.Frame(page,bg=BG);line.pack(fill='x',pady=(0,10))
        self.search=tk.StringVar();entry=ttk.Entry(line,textvariable=self.search);entry.pack(side='left',fill='x',expand=True)
        self.category=tk.StringVar(value='全部');combo=ttk.Combobox(line,textvariable=self.category,state='readonly',width=11,values=['全部','BOT','回合','经济','玩家','生化','环境','查询','其他']);combo.pack(side='left',padx=(10,0))
        self.catalog_count=label(page,'',True,9,bg=BG);self.catalog_count.pack(anchor='w',pady=(0,8))
        f=tk.Frame(page,bg=INPUT);f.pack(fill='both',expand=True)
        self.catalog_tree=ttk.Treeview(f,columns=('name','kind','desc'),show='headings',height=6)
        for key,title,width in [('name','命令 / 变量',245),('kind','类型',65),('desc','说明',440)]:
            self.catalog_tree.heading(key,text=title);self.catalog_tree.column(key,width=width,minwidth=50,stretch=key=='desc')
        bar=ttk.Scrollbar(f,orient='vertical',command=self.catalog_tree.yview);self.catalog_tree.configure(yscrollcommand=bar.set)
        bar.pack(side='right',fill='y');self.catalog_tree.pack(fill='both',expand=True)
        self.catalog_tree.bind('<<TreeviewSelect>>',self.catalog_select)
        detail=tk.Frame(page,bg=CARD,highlightbackground=BORDER,highlightthickness=1);detail.pack(side='bottom',fill='x',pady=(8,0),before=f)
        self.detail=label(detail,'输入名称或中文功能关键词搜索。选择一项后可查看原生帮助。',True,9,wraplength=750,justify='left');self.detail.pack(anchor='w',padx=12,pady=(8,6))
        detail.bind('<Configure>',lambda e:self.detail.configure(wraplength=max(200,e.width-26)))
        line=tk.Frame(detail,bg=CARD);line.pack(fill='x',padx=15,pady=(0,13))
        self.catalog_command=tk.StringVar();ttk.Entry(line,textvariable=self.catalog_command).pack(side='left',fill='x',expand=True)
        self.feature_control(ttk.Button(line,text='发送',style='Accent.TButton',command=lambda:self.send_command(self.catalog_command.get())),'commands',lambda:self.catalog_command.get()).pack(side='left',padx=(10,8))
        ttk.Button(line,text='存为自定义',style='Small.TButton',command=self.catalog_to_custom).pack(side='left')
        self.search.trace_add('write',self.schedule_filter);self.category.trace_add('write',self.schedule_filter);self.filter_catalog()
    def schedule_filter(self,*_):
        if self.filter_job:self.root.after_cancel(self.filter_job)
        self.filter_job=self.root.after(140,self.filter_catalog)
    def filter_catalog(self):
        self.filter_job=None;q=self.search.get().lower().strip();category=self.language.source(self.category.get())
        self.catalog_matches=[r for r in DATA['catalog'] if (category=='全部' or category==r.get('category','其他')) and all(part in (r['name']+' '+r.get('zh','')+' '+r.get('help','')).lower() for part in q.split())]
        for iid in self.catalog_tree.get_children():self.catalog_tree.delete(iid)
        for i,r in enumerate(self.catalog_matches):
            desc=(r.get('zh') if self.language.lang=='zh' else r.get('help')) or r['help'] or '无原生帮助文本'
            self.catalog_tree.insert('', 'end',iid=str(i),values=(r['name'],self.language.t({'variable':'变量','command':'命令','handler':'路由'}[r['kind']]),self.language.t(desc).replace('\n',' ')[:150]))
        self.catalog_count.configure(text=f'{len(self.catalog_matches):,} 项结果 · 已确认登记不代表所有模式都允许执行')
    def selected_catalog(self):
        selected=self.catalog_tree.selection()
        return self.catalog_matches[int(selected[0])] if selected else None
    def catalog_select(self,_=None):
        r=self.selected_catalog()
        if not r:return
        restrictions=[]
        flags=0
        for source in r['sources']:flags|=source['flags']
        if flags&0x4000:restrictions.append('作弊标志')
        if flags&2:restrictions.append('开发者标志')
        if flags&16:restrictions.append('隐藏标志')
        default=(' · 默认 '+repr(r['default'])) if r['kind']=='variable' else ''
        source=' / '.join(s['module'].replace('.dll','') for s in r['sources'])
        help_text=r.get('zh') or r['help'] or '游戏没有提供帮助文本；请确认参数后再发送。'
        self.detail.configure(text=f'{r["name"]}{default} · {source}\n'+help_text[:260]+('\n限制：'+'、'.join(restrictions) if restrictions else ''))
        self.catalog_command.set(r.get('example') or r['name'])
    def catalog_to_custom(self):
        r=self.selected_catalog()
        if not r:self.log('请先选择一条命令',True);return
        self.add_custom(r['name'],self.catalog_command.get());self.command_tabs.select(1);self.log('已加入自定义；设置会自动保存。')
    def send_command(self,text):
        try:command_bytes(text)
        except ValueError as ex:self.log(str(ex),True);return
        self.request('command',text=text.strip())
    def request(self,action,require_ready=True,**data):
        if action in ('stop','disconnect'):self.auto_connect=False
        elif action=='connect':self.auto_connect=True;self.ensure_worker()
        if require_ready and not self.ready:
            if action=='cheats':self.vars['cheats'].set(self.last_cheats)
            self.log('请先连接游戏并进入对局',True);self.reset_flags();return
        feature={'once':data.get('field'),'round_setting':data.get('field'),'ammo':'ammo','buy':'buy','scale':'scale','ghost':'ghost','cheats':'cheats','mutation_read':'mutation_read','heroes':'heroes','heroes_temple':'heroes','heroes_auto':'heroes','heroes_no_wait':'heroes','heroes_upgrade':'heroes_upgrade','heroes_model':'heroes_model','heroes_custom_damage':'heroes_custom_damage','heroes_no_attack':'heroes_no_attack','weapon_spawn':'weapon_spawn','mutation_add':'mutation','machine_scan':'machine','machine_reroll':'machine','command':'commands','chat':'chat','chat_timer':'chat'}.get(action)
        if require_ready and feature and data.get('enabled',True) and not self.capabilities.get(feature,{}).get('available',False):
            self.log(self.capabilities.get(feature,{}).get('reason','当前功能不可用'),True);self.apply_capabilities();return
        if self.worker:
            if action=='connect':data['preferences']=dict(enabled=self.vars['each_round'].get(),cheats=self.cheats_desired,features=dict(self.feature_preferences))
            accepted=self.worker.submit(action,epoch=self.epoch,**data)
            if accepted:
                if action in ('ammo','buy','scale') and data.get('persist',True):
                    value=bool(data['enabled'])
                    if action=='scale' and value:value=dict(head=data['head'],body=data['body'],uniform=data['uniform'],factor=data['factor'])
                    self.feature_preferences[action]=value;self.schedule_save()
                    self.worker.submit('each_round',enabled=self.vars['each_round'].get(),cheats=self.cheats_desired,features=dict(self.feature_preferences))
                title={'connect':'连接游戏','disconnect':'断开游戏','stop':'停止全部','once':'设置玩家数值','round_setting':'每局设置','player_action':{'vote':'投票踢出','kick':'无票踢出','goto':'传送到此人身边','bring':'将此人传送过来'}.get(data.get('operation'),'玩家操作'),'locks':'锁定玩家数值','ammo':'无限子弹','buy':'随时购买','scale':'模型比例','ghost':('幽灵显形' if data.get('enabled') else '幽灵隐身'),'cheats':'作弊开关','heroes':{'kill':'怪物直接死亡','finish':'快速完成当前波','jump':'跳转波次'}.get(data.get('operation'),'洛奇功能'),'heroes_temple':'神殿保护','heroes_auto':'怪物自动死亡','heroes_no_wait':'跳过等待','heroes_upgrade':'全体玩家强化','heroes_model':'玩家模型切换','heroes_custom_damage':'所有玩家自定义伤害','heroes_no_attack':'怪物不攻击玩家','weapon_spawn':'地面刷枪','mutation_add':'增加变异','mutation_read':'读取变异','machine_scan':'刷新机器','machine_reroll':'重抽机器技能','chat':'立即喊话','chat_timer':'定时喊话'}.get(action,action)
                self.log('已提交：'+(data.get('text','') if action=='command' else title)+'；等待游戏处理。')
            return bool(accepted)
        else:self.log('离线界面检查：未执行游戏操作');return False
    def ensure_worker(self):
        if self.closing or self.worker is None or self.worker.is_alive():return False
        self.worker=Worker(self.events,DATA['caps']);self.worker.each_round=self.vars['each_round'].get();self.worker.cheats_desired=self.cheats_desired
        self.worker.feature_preferences=dict(self.feature_preferences);self.worker.start()
        self.log('连接工作线程已恢复，继续自动发现游戏。');return True
    def stop(self):
        self.invulnerable_targets.clear();self.ghost_targets.clear()
        for key in ('hp_lock_mode','money_lock_mode','invulnerable_mode'):self.vars[key].set(False)
        self.request('stop',require_ready=False)
    def reset_flags(self):
        self.invulnerable_targets.clear();self.ghost_targets.clear()
        for key in ('hp','money','ammo','scale','buy','chat','round_hp','round_money','invulnerable','heroes_auto','heroes_no_wait','heroes_custom_damage','heroes_no_attack'):self.vars[key].set(False)
    def resize_player_columns(self):
        # Measure the actual Tk fonts: translations and Windows scaling both
        # change glyph widths. Keep the complete status text, not an abbreviation.
        from tkinter import font as tkfont
        tree=self.player_tree;style=ttk.Style(self.root)
        body=tkfont.Font(root=self.root,font=style.lookup('Treeview','font'))
        heading=tkfont.Font(root=self.root,font=style.lookup('Treeview.Heading','font'))
        alive=self.language.t('存活');dead=self.language.t('死亡')
        samples={'check':['☑','☐'],'index':['64'],'hp':['999999'],'money':['999999'],
                 'team':[self.language.t('观战'),'CT','T'],
                 'state':[alive,dead,alive+' · '+self.language.t('无敌')]}
        floors={'check':48,'index':48,'hp':95,'money':100,'team':65,'state':128}
        changed=False
        for column,values in samples.items():
            values+= [str(tree.set(iid,column)) for iid in tree.get_children()]
            width=max(floors[column],heading.measure(str(tree.heading(column,'text')))+24,
                      max(body.measure(value) for value in values)+24)
            if int(tree.column(column,'width'))!=width or int(tree.column(column,'minwidth'))!=width:
                tree.column(column,width=width,minwidth=width,stretch=False);changed=True
        if changed:self.queue_window_fit()
    def player_status(self,p):
        if not p.alive:return self.language.t('死亡')
        parts=[self.language.t('存活')]
        if p.damage_mode==0:parts.append(self.language.t('无敌'))
        if p.team==2 and p.ghost_alpha is not None and self.capabilities.get('ghost',{}).get('available',False):
            parts.append(self.language.t('显形' if p.ghost_alpha==255 else '隐身'))
        return ' · '.join(parts)
    def update_players(self,rows):
        # Group CT, T and spectators; keep the game's real slot IDs intact.
        team_order={3:0,2:1,1:2}
        rows=sorted(rows,key=lambda p:(team_order.get(p.team,3),p.team,p.key.index))
        self.players={str(p.key.index):p for p in rows};valid={p.key for p in rows};self.checked.intersection_update(valid)
        existing=set(self.player_tree.get_children())
        for iid,p in self.players.items():
            values=('☑' if p.key in self.checked else '☐',p.key.index,p.name+('  · '+self.language.t('自己') if p.local else ''),p.health,('—' if p.money<0 else p.money),self.language.t({1:'观战',2:'T',3:'CT'}.get(p.team,str(p.team))),self.player_status(p))
            tags=('invulnerable',) if p.alive and p.damage_mode==0 else ()
            if iid in existing:self.player_tree.item(iid,values=values,tags=tags)
            else:self.player_tree.insert('','end',iid=iid,values=values,tags=tags)
        for iid in existing-set(self.players):self.player_tree.delete(iid)
        order=tuple(self.players)
        if tuple(self.player_tree.get_children())!=order:
            # Moving existing items retains their selection, focus and checkbox identity.
            for position,iid in enumerate(order):self.player_tree.move(iid,'',position)
        if rows:self.empty_label.place_forget()
        else:self.empty_label.place(relx=.5,rely=.5,anchor='center')
        self.resize_player_columns();self.draw_selection();self.update_player_actions()
    def poll(self):
        try:
            while True:
                kind,data=self.events.get_nowait()
                if kind=='state':
                    self.capabilities=data.get('capabilities',{});self.command_states=data.get('command_status',{})
                    self.ready=data['ready'];self.epoch=data.get('epoch',-1);self.status.configure(text=('●  ' if self.ready else '○  ')+data['text'],fg=GREEN if self.ready else MUTED)
                    self.update_players(data.get('players',[]))
                    if 'cheats' in data:self.last_cheats=data['cheats'];self.vars['cheats'].set(data['cheats'])
                elif kind=='connection':
                    self.needs_admin=bool(data.get('requires_admin'));self.connect_button.configure(text='管理员连接' if self.needs_admin else '连接游戏')
                    self.status.configure(text='○ '+('连接受阻 · 需要管理员权限 · 自动重试中' if self.needs_admin and data.get('retrying') else data['text']),fg=MUTED if data.get('connected') or data.get('retrying') or data.get('pending') else RED)
                elif kind in ('log','error'):self.log(data['text'],kind=='error')
                elif kind=='reset':
                    self.reset_flags();self.checked.clear();self.draw_selection();self.machine_rows=[];self.machine_choice.set('');self.machine_box.configure(values=[])
                    self.bio_status.configure(text='进入生化 ZETA 后可读取次数和机器列表。')
                    self.heroes_damage_note.configure(text='当前使用原生伤害')
                    self.update_heroes_models([]);self.update_heroes_levels([]);self.vars['heroes_temple'].set(False);self.heroes_status.configure(text='仅本地房主的洛奇英雄传对局可用。')
                elif kind=='heroes_models':self.update_heroes_models(data['rows'],data.get('reason',''))
                elif kind=='heroes_levels':self.update_heroes_levels(data['rows'],data.get('reason',''))
                elif kind=='heroes_state':
                    self.heroes_status.configure(text=data['text']);self.vars['heroes_temple'].set(data['protected'])
                elif kind=='bio_state':self.bio_status.configure(text=data['text'])
                elif kind=='machines':
                    self.machine_rows=data['rows'];self.machine_box.configure(values=[f'#{r.key.index} · 技能 {r.skill} · '+('已启用' if r.enabled else '未启用') for r in self.machine_rows])
                    if self.machine_rows:self.machine_box.current(0)
                    else:self.machine_choice.set('当前地图没有变异机器')
                elif kind=='invulnerability_targets':
                    self.invulnerable_targets=set(data['keys']);self.vars['invulnerable_auto'].set(data['auto']);self.refresh_invulnerability_ui()
                elif kind=='ghost_targets':
                    self.ghost_targets=set(data['keys']);self.update_player_actions()
                elif kind=='flags':
                    for k,v in data.items():self.vars[k].set(v)
                elif kind=='closed':
                    if self.closing:self.root.destroy();return
        except queue.Empty:pass
        self.apply_capabilities()
        if not self.closing and self.auto_connect and self.ensure_worker():
            self.worker.submit('connect',game=self.game_directory)
        if self.root.winfo_exists():self.root.after(100,self.poll)
    def log(self,text,error=False):
        text=str(text);line=time.strftime('%H:%M:%S')+'  '+self.language.t(text)
        self.logs.append(line);self.logs=self.logs[-500:]
        preview=text.replace('\r',' ').replace('\n',' ')
        if len(preview)>100:preview=preview[:99]+'…'
        self.hint.configure(text=preview,fg=RED if error else MUTED)
        self.log_text.configure(state='normal');self.log_text.insert('end',line+'\n','error' if error else 'normal')
        self.log_text.tag_config('error',foreground=RED)
        if int(self.log_text.index('end-1c').split('.')[0])>200:self.log_text.delete('1.0','2.0')
        self.log_text.see('end');self.log_text.configure(state='disabled')
        if self.persist_logs:
            try:
                if self.log_path.exists() and self.log_path.stat().st_size>1048576:self.log_path.replace(self.log_path.with_suffix('.log.1'))
                with self.log_path.open('a',encoding='utf-8') as f:
                    f.write(time.strftime('%Y-%m-%d %H:%M:%S')+(' [错误] ' if error else ' [操作] ')+text.replace('\n',' | ')+'\n')
            except OSError:self.hint.configure(text=preview+'（日志文件无法写入）',fg=RED)
    def collect_settings(self):
        settings={k:self.vars[k].get() for k in ('hp_value','money_value','head','body','model_scale','scale_uniform','invulnerable_auto','interval','chat_team','bot_count','mutation_count','heroes_wave','heroes_seconds','heroes_atk','heroes_hp','heroes_damage_value','each_round')}
        for field in ('heroes_atk','heroes_hp'):settings[field]=self.language.source(settings[field])
        settings['custom']=[[name.get(),value.get()] for _,name,value in self.custom]
        settings['game_directory']=self.game_directory
        settings.update({key+'_mode':mode for key,mode in self.action_modes.items()})
        settings['chat_text']=self.chat_text.get('1.0','end-1c')
        settings['cheats_desired']=self.cheats_desired;settings['difficulty']=self.difficulty.current()
        settings['feature_preferences']=dict(self.feature_preferences)
        return settings
    def watch_setting(self,var):
        previous=[var.get()]
        def changed(*_):
            value=var.get()
            if value!=previous[0]:previous[0]=value;self.schedule_save()
        var.trace_add('write',changed)
    def watch_settings(self):
        for key in ('hp_value','money_value','head','body','model_scale','scale_uniform','invulnerable_auto','interval','chat_team','bot_count','mutation_count','heroes_wave','heroes_seconds','heroes_atk','heroes_hp','heroes_damage_value','each_round'):
            self.watch_setting(self.vars[key])
        self.chat_text.edit_modified(False)
        def changed(_):
            if self.chat_text.edit_modified():
                self.chat_text.edit_modified(False);self.schedule_save()
        self.chat_text.bind('<<Modified>>',changed,add='+')
    def schedule_save(self,*_):
        if self.settings_loading or self.closing:return
        now=time.monotonic()
        if self.save_dirty_at is None:self.save_dirty_at=now
        if self.save_job is not None:self.root.after_cancel(self.save_job)
        delay=max(1,min(500,int((self.save_dirty_at+2.-now)*1000)))
        self.save_job=self.root.after(delay,self.save)
    def save(self):
        if self.save_job is not None:self.root.after_cancel(self.save_job);self.save_job=None
        self.save_dirty_at=None
        settings=self.collect_settings()
        if settings==self.saved_settings:return True
        try:
            self.digest=portable_save(self.path,settings,self.digest);self.saved_settings=settings;return True
        except Exception as ex:self.log('自动保存失败：'+str(ex),True);return False
    def load_settings_into_ui(self,settings):
        defaults=dict(hp_value='9999',money_value='99999',head='1',body='1',model_scale='1',scale_uniform=False,
                      invulnerable_auto=True,interval='10',chat_team='all',bot_count='10',mutation_count='1',heroes_wave='1',heroes_seconds='3',heroes_atk='',heroes_hp='',heroes_damage_value='999999999',each_round=False)
        self.settings_loading=True
        try:
            for key,value in defaults.items():self.vars[key].set(settings.get(key,value))
            self.game_directory=settings.get('game_directory','');self.cheats_desired=bool(settings.get('cheats_desired',False))
            self.feature_preferences=dict(settings.get('feature_preferences',{}))
            if not self.ready:self.vars['cheats'].set(self.cheats_desired)
            for key in ('hp','money'):self.set_action_mode(key,settings.get(key+'_mode','once'))
            self.chat_text.delete('1.0','end');self.chat_text.insert('1.0',settings.get('chat_text',''))
            self.difficulty.current(settings.get('difficulty',7))
            for item in list(self.custom):self.delete_custom(item)
            for title,command in settings.get('custom',DATA['custom']):self.add_custom(title,command)
            self.update_scale_inputs();self.refresh_invulnerability_ui()
        finally:self.settings_loading=False
    def restore_defaults(self):
        undoing=self.undo_defaults is not None
        before=self.collect_settings()
        target=self.undo_defaults if undoing else {}
        live={key:bool(self.vars[key].get()) for key in ('cheats','ammo','buy','scale')}
        if not undoing:
            self.undo_runtime=dict(live,head=self.vars['head'].get(),body=self.vars['body'].get(),
                                   uniform=self.vars['scale_uniform'].get(),factor=self.vars['model_scale'].get())
        self.load_settings_into_ui(target)
        if not self.save():
            self.load_settings_into_ui(before)
            if not undoing:self.undo_runtime=None
            return
        if not undoing and self.worker:self.worker.submit('reset_defaults')
        self.change_each_round()
        desired=self.undo_runtime if undoing else {'cheats':False,'ammo':False,'buy':False,'scale':False}
        if self.ready:
            for key in ('ammo','buy'):
                if undoing or live[key]!=desired[key]:self.request(key,enabled=desired[key],persist=False)
            if undoing or live['scale']!=desired['scale']:
                self.request('scale',enabled=desired['scale'],head=desired.get('head','1'),
                             body=desired.get('body','1'),uniform=desired.get('uniform',False),
                             factor=desired.get('factor','1'),persist=False)
            if undoing or live['cheats']!=desired['cheats']:self.request('cheats',enabled=desired['cheats'])
        self.undo_defaults=None if undoing else before
        if undoing:self.undo_runtime=None
        self.defaults_button.configure(text=self.language.t('恢复默认值' if undoing else '撤销恢复默认值'),
                                       style='TButton' if undoing else 'Undo.TButton')
        self.log('已撤销恢复默认值，设置已自动保存' if undoing else '已恢复默认值；关闭工具前可撤销')
    def export_copy(self):
        dest=filedialog.asksaveasfilename(parent=self.root,title='导出带当前配置的便携副本',defaultextension='.pyw',initialfile=TITLE+'-便携副本.pyw',filetypes=[('Python 无控制台脚本','*.pyw')])
        if not dest:return
        try:
            target=Path(dest)
            if target.resolve()==self.path.resolve():self.save();return
            shutil.copyfile(self.path,target);portable_save(target,self.collect_settings());self.log('便携副本已导出：'+str(target))
        except Exception as ex:self.log('导出失败：'+str(ex),True)
    def callback_error(self,kind,error,tb):
        import traceback
        self.log('界面错误：'+str(error),True)
        path=self.path.with_suffix('.error.log')
        try:path.write_text(''.join(traceback.format_exception(kind,error,tb)),encoding='utf-8')
        except OSError:pass
    def mousewheel(self,event):
        if self._is_combobox_popup_path(getattr(event,'widget','')):
            # This is the trailing 'all' binding: native Listbox scrolling
            # has already run. Do not scroll the background page as well.
            return 'break'
        widget=event.widget
        if isinstance(widget,(ttk.Treeview,tk.Text,ttk.Combobox)):return
        while widget is not None:
            if isinstance(widget,ScrollFrame):return widget.wheel(event)
            widget=getattr(widget,'master',None)
    def reveal(self):
        self.fit_window();self.root.update_idletasks();dark_titlebar(self.root)
        self.root.deiconify();self.root.update_idletasks();dark_titlebar(self.root)
    def close(self):
        if self.closing:return
        self.save()
        self.undo_defaults=None;self.undo_runtime=None
        self.auto_connect=False
        self.closing=True;self.status.configure(text='正在停止持续功能并关闭…',fg=MUTED)
        if self.worker:self.worker.quit.set()
        else:self.root.destroy()

    def remember_page(self):
        selected=self.tabs.select()
        self.current_page=next((key for key,frame in self.pages.items() if str(frame)==selected),self.current_page)

    def weapon_command(self):
        i=self.weapon_box.current()
        return 'ent_create '+self.weapon_rows[i]['name'] if 0<=i<len(self.weapon_rows) else ''

    def store_manual(self):
        text=self.manual_command.get().strip()
        try:command_bytes(text)
        except ValueError as ex:self.log(str(ex),True);return
        self.add_custom('新指令',text);self.command_tabs.select(1)
        self.log('已加入自定义；设置会自动保存。')

    def toggle_log(self):
        if self.log_frame.winfo_manager():self.log_frame.pack_forget();self.log_button.configure(text='展开日志')
        else:self.log_frame.pack(fill='x',pady=(7,0));self.log_button.configure(text='收起日志')
        self.queue_window_fit()

    def open_log(self):
        if self.log_path.is_file():
            import os
            os.startfile(str(self.log_path))
        else:self.log('还没有保存的操作日志。')

# GitHub release updates: repository identity survives repository renames/transfers.
APP_ID = 'cso2-host-tool'
APP_VERSION = '1.0.0'
UPDATE_REPOSITORY_ID = 1410625177
UPDATE_PROTOCOL = 1
UPDATE_TAG_PREFIX = 'host-tool-v'
UPDATE_MAX_BYTES = 8 * 1024 * 1024


def update_version(value):
    match = re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', str(value))
    if not match:
        raise ValueError('Invalid release version')
    return tuple(map(int, match.groups()))


def update_url(value, api=False):
    from urllib.parse import urlsplit
    parsed = urlsplit(value)
    allowed = {'api.github.com'} if api else {'github.com', 'release-assets.githubusercontent.com',
                                             'objects.githubusercontent.com', 'api.github.com'}
    if parsed.scheme != 'https' or parsed.hostname not in allowed or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError('Untrusted update URL')
    return value


def update_fetch(url, limit, api=False):
    import urllib.request
    class GitHubRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            update_url(newurl, api=api)
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    headers = {'User-Agent': 'CSO2-Host-Tool/' + APP_VERSION,
               'Accept': 'application/vnd.github+json' if api else 'application/octet-stream'}
    if api:
        headers['X-GitHub-Api-Version'] = '2022-11-28'
    request = urllib.request.Request(update_url(url, api), headers=headers)
    with urllib.request.build_opener(GitHubRedirect).open(request, timeout=15) as response:
        update_url(response.url, api)
        if int(response.headers.get('Content-Length', '0')) > limit:
            raise ValueError('Update download is too large')
        payload = response.read(limit + 1)
    if len(payload) > limit:
        raise ValueError('Update download is too large')
    return payload


def update_json(url, api=True):
    return json.loads(update_fetch(url, 4 * 1024 * 1024 if api else 65536, api))


def discover_host_update(fetch_json=None):
    import base64
    from urllib.parse import quote
    fetch_json = fetch_json or update_json
    repository = fetch_json(f'https://api.github.com/repositories/{UPDATE_REPOSITORY_ID}')
    if repository.get('id') != UPDATE_REPOSITORY_ID:
        raise ValueError('Update repository identity mismatch')
    api_url = update_url(repository['url'], api=True)
    candidates = []
    for page in range(1, 11):
        releases = fetch_json(f'{api_url}/releases?per_page=100&page={page}')
        if not isinstance(releases, list):
            raise ValueError('Invalid GitHub releases response')
        for release in releases:
            tag = str(release.get('tag_name', ''))
            if release.get('draft') or release.get('prerelease') or not tag.startswith(UPDATE_TAG_PREFIX):
                continue
            try:
                number = update_version(tag[len(UPDATE_TAG_PREFIX):])
            except ValueError:
                continue
            if number > update_version(APP_VERSION):
                candidates.append((number, release))
        if len(releases) < 100:
            break
    if not candidates:
        return None
    branch = quote(repository['default_branch'], safe='')
    tree = fetch_json(f'{api_url}/git/trees/{branch}?recursive=1')
    if tree.get('truncated') or not isinstance(tree.get('tree'), list):
        raise ValueError('Incomplete update source tree')
    for _, release in sorted(candidates, key=lambda row: row[0], reverse=True):
        suffix = '/releases/' + release['tag_name'] + '/' + APP_ID + '.release.json'
        rows = [r for r in tree['tree'] if r.get('type') == 'blob' and r.get('path', '').endswith(suffix)]
        if not rows:
            continue
        if len(rows) != 1 or rows[0].get('size', 0) > 65536:
            raise ValueError('HOST TOOL source manifest is ambiguous or oversized')
        blob = fetch_json(update_url(rows[0]['url'], api=True))
        if blob.get('encoding') != 'base64':
            raise ValueError('Invalid source manifest encoding')
        manifest = json.loads(base64.b64decode(blob['content']))
        release_version = release['tag_name'][len(UPDATE_TAG_PREFIX):]
        if (manifest.get('schema') != 1 or manifest.get('product') != APP_ID
                or manifest.get('version') != release_version or manifest.get('repository_id') != UPDATE_REPOSITORY_ID):
            raise ValueError('Invalid HOST TOOL source manifest')
        assets = [a for a in release.get('assets', []) if a.get('name') == manifest.get('asset') and a.get('state') == 'uploaded']
        if len(assets) != 1 or not str(assets[0]['name']).lower().endswith('.pyw'):
            raise ValueError('HOST TOOL attachment is missing or ambiguous')
        script = assets[0]; checksum = manifest.get('sha256', ''); size = manifest.get('size')
        if (not re.fullmatch('[0-9a-f]{64}', checksum) or type(size) is not int
                or not 0 < size <= UPDATE_MAX_BYTES or script.get('size') != size):
            raise ValueError('Invalid HOST TOOL checksum or size')
        if script.get('digest') and script['digest'] != 'sha256:' + checksum:
            raise ValueError('HOST TOOL checksum does not match GitHub')
        return dict(version=release_version, sha256=checksum, size=size,
                    download_url=update_url(script['browser_download_url']), page_url=update_url(release['html_url']))
    return None


def validate_update_source(payload, version):
    import ast
    if not 0 < len(payload) <= UPDATE_MAX_BYTES:
        raise ValueError('Invalid update size')
    source = payload.decode('utf-8-sig')
    tree = ast.parse(source)
    wanted = {'APP_ID': APP_ID, 'APP_VERSION': version, 'UPDATE_REPOSITORY_ID': UPDATE_REPOSITORY_ID,
              'UPDATE_PROTOCOL': UPDATE_PROTOCOL}
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in wanted:
                    if target.id in values:
                        raise ValueError('Duplicate update identity')
                    values[target.id] = ast.literal_eval(node.value)
    if values != wanted:
        raise ValueError('Downloaded script is not a compatible HOST TOOL release')
    if len(re.findall(r'^_PORTABLE_SETTINGS_B64 = "[A-Za-z0-9+/=]*"$', source, re.M)) != 1:
        raise ValueError('Downloaded script does not support portable settings')
    compile(source, '<HOST TOOL update>', 'exec')
    return source


def prepare_host_update(target, info, settings, fetch=None):
    import secrets
    target = Path(target).resolve()
    if target.with_name(target.name + '.OLD').exists():
        raise RuntimeError('An OLD backup already exists. Finish or recover the previous update first.')
    payload = (fetch or update_fetch)(info['download_url'], UPDATE_MAX_BYTES)
    if len(payload) != info['size'] or hashlib.sha256(payload).hexdigest() != info['sha256']:
        raise ValueError('Downloaded update failed SHA-256 verification')
    validate_update_source(payload, info['version'])
    token = secrets.token_hex(16)
    staged = target.parent / ('.cso2-update-' + token + '.pyw')
    ticket = target.parent / ('.cso2-update-' + token + '.json')
    try:
        with staged.open('xb') as stream:
            stream.write(payload);stream.flush();os.fsync(stream.fileno())
        staged_digest = portable_save(staged, settings)
        plan = dict(schema=1, product=APP_ID, repository_id=UPDATE_REPOSITORY_ID, token=token,
                    target=target.name, version=info['version'], parent_pid=os.getpid(),
                    before_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                    after_sha256=staged_digest)
        with ticket.open('x', encoding='utf-8') as stream:
            json.dump(plan, stream);stream.flush();os.fsync(stream.fileno())
        return ticket
    except Exception:
        staged.unlink(missing_ok=True);ticket.unlink(missing_ok=True)
        raise


def read_update_ticket(ticket):
    ticket = Path(ticket).resolve()
    if ticket.stat().st_size > 16384:
        raise ValueError('Invalid update ticket')
    plan = json.loads(ticket.read_text(encoding='utf-8'))
    token = plan.get('token', '')
    name = plan.get('target', '')
    if plan.get('schema') != 1 or plan.get('product') != APP_ID or plan.get('repository_id') != UPDATE_REPOSITORY_ID:
        raise ValueError('Invalid update ticket identity')
    if not re.fullmatch('[0-9a-f]{32}', token) or ticket.name != '.cso2-update-' + token + '.json':
        raise ValueError('Invalid update ticket name')
    if not isinstance(name, str) or Path(name).name != name or any(c in name for c in '/\\:') or not name.lower().endswith('.pyw'):
        raise ValueError('Invalid update target')
    for key in ('before_sha256', 'after_sha256'):
        if not re.fullmatch('[0-9a-f]{64}', str(plan.get(key, ''))):
            raise ValueError('Invalid update ticket checksum')
    update_version(plan['version'])
    target = ticket.parent / name
    staged = ticket.with_suffix('.pyw')
    ready = ticket.with_suffix('.ready')
    old = target.with_name(target.name + '.OLD')
    return plan, target, staged, ready, old


def acknowledge_host_update(ticket, running_path):
    plan, target, staged, ready, old = read_update_ticket(ticket)
    if target.resolve() != Path(running_path).resolve() or plan['version'] != APP_VERSION:
        raise ValueError('Update startup identity mismatch')
    # Called from Tk's event loop after the new window has rendered successfully.
    with ready.open('x', encoding='ascii') as stream:
        stream.write(plan['token']);stream.flush();os.fsync(stream.fileno())


def update_wait_parent(pid, timeout=45):
    if type(pid) is not int or pid <= 0 or pid == os.getpid():
        raise ValueError('Invalid updater parent process')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD];kernel.OpenProcess.restype = W.HANDLE
    kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD];kernel.WaitForSingleObject.restype = W.DWORD
    kernel.CloseHandle.argtypes = [W.HANDLE];kernel.CloseHandle.restype = W.BOOL
    handle = kernel.OpenProcess(0x100000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return
        raise OSError('Cannot verify that the old application has exited')
    try:
        if kernel.WaitForSingleObject(handle, int(timeout * 1000)) != 0:
            raise TimeoutError('The old application did not stop; its file has not been replaced')
    finally:
        kernel.CloseHandle(handle)


def update_spawn(arguments):
    import subprocess
    return subprocess.Popen([sys.executable, *map(str, arguments)], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), close_fds=True)


def apply_host_update(ticket, wait_parent=None, spawn=None, timeout=60, notify=None):
    import subprocess
    plan, target, staged, ready, old = read_update_ticket(ticket)
    launch = spawn or update_spawn
    report = notify or (lambda text: ctypes.windll.user32.MessageBoxW(None, text, 'CSO2 Host Tool Update', 0x10))
    moved = False;installed = False;confirmed = False;child = None
    try:
        (wait_parent or update_wait_parent)(plan['parent_pid'])
        if old.exists():
            raise RuntimeError('OLD backup already exists; refusing to overwrite it')
        if hashlib.sha256(target.read_bytes()).hexdigest() != plan['before_sha256']:
            raise RuntimeError('The local script changed during download; update cancelled')
        payload = staged.read_bytes()
        if hashlib.sha256(payload).hexdigest() != plan['after_sha256']:
            raise ValueError('Staged update changed after verification')
        validate_update_source(payload, plan['version'])
        os.rename(target, old);moved = True
        os.replace(staged, target);installed = True
        child = launch([target, '--update-ticket', ticket])
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError('The new application exited before confirming startup')
            if ready.exists() and ready.read_text(encoding='ascii') == plan['token']:
                confirmed = True
                if hashlib.sha256(old.read_bytes()).hexdigest() != plan['before_sha256']:
                    raise RuntimeError('The OLD backup changed; it has been retained')
                old.unlink();ready.unlink(missing_ok=True);Path(ticket).unlink(missing_ok=True)
                return True
            time.sleep(0.1)
        raise TimeoutError('The new application did not confirm startup')
    except Exception as error:
        if confirmed:
            report('新版已启动，旧文件清理未完成。 / The update started; backup cleanup is incomplete.\n' + str(error))
            return True
        if child is not None and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
        recovered = False
        if moved and old.exists() and hashlib.sha256(old.read_bytes()).hexdigest() == plan['before_sha256']:
            try:
                if installed and target.exists():
                    # Keep the unsuccessful new script for inspection instead of discarding it.
                    os.replace(target, staged)
                os.replace(old, target);recovered = True
                launch([target, '--skip-update-once'])
            except OSError:
                pass
        ready.unlink(missing_ok=True)
        report(('更新失败，已恢复旧版。 / Update failed; the previous version was restored.\n'
                if recovered else '更新未完成，旧文件已保留。 / Update not completed; the previous file was retained.\n') + str(error))
        return False


class HostReleaseUpdater:
    def __init__(self, app, automatic=True):
        self.app = app;self.root = app.root;self.inbox = queue.Queue();self.busy = False
        self.notified = set();self.dialog = None;self.info = None
        self.root.after(200, self.poll)
        if automatic:self.root.after(4000, self.periodic)

    def text(self, zh, en):
        return zh if self.app.language.lang == 'zh' else en

    def periodic(self):
        if self.app.closing:return
        self.check()
        self.root.after(6 * 60 * 60 * 1000, self.periodic)

    def background(self, operation, success, manual=False):
        if self.busy:return
        self.busy = True;self.app.update_button.state(['disabled'])
        def work():
            try:self.inbox.put((success, operation(), manual))
            except Exception as error:self.inbox.put(('error', str(error), manual))
        threading.Thread(target=work, name='host-release-update', daemon=True).start()

    def check(self, manual=False):
        if self.app.closing:return
        self.background(discover_host_update, 'checked', manual)

    def show_release(self, info):
        if self.dialog is not None and self.dialog.winfo_exists():
            self.dialog.lift();return
        self.info = info
        dialog = self.dialog = tk.Toplevel(self.root);dialog.withdraw();dialog.title('CSO2 Host Tool Update')
        dialog.configure(bg=CARD);dialog.transient(self.root);dialog.resizable(False, False)
        frame = tk.Frame(dialog, bg=CARD, padx=20, pady=18);frame.pack()
        label(frame, self.text('发现新版本', 'Update available'), size=13).pack(anchor='w')
        label(frame, f"v{APP_VERSION}  →  v{info['version']}").pack(anchor='w', pady=(8, 8))
        label(frame, self.text('自动更新会保留当前配置并重启工具。\n新版启动成功后，才会删除 OLD 旧文件。',
                              'Automatic update keeps your settings and restarts the tool.\nThe OLD file is removed only after the new window starts.'),
              True, wraplength=480, justify='left').pack(anchor='w')
        buttons = tk.Frame(frame, bg=CARD);buttons.pack(fill='x', pady=(16, 0))
        self.download_button = ttk.Button(buttons, text=self.text('自动下载并更新', 'Download and update'), command=self.download)
        self.download_button.pack(side='left')
        def open_page():
            import webbrowser
            webbrowser.open(update_url(info['page_url']))
        ttk.Button(buttons, text=self.text('打开网页手动更新', 'Open release page'), command=open_page).pack(side='left', padx=8)
        ttk.Button(buttons, text=self.text('稍后', 'Later'), command=dialog.destroy).pack(side='left')
        self.progress = label(frame, '', True, wraplength=480, justify='left');self.progress.pack(anchor='w', pady=(10, 0))
        dialog.update_idletasks();dialog.deiconify();dark_titlebar(dialog)

    def download(self):
        if self.busy or self.app.closing:return
        self.download_button.state(['disabled'])
        self.progress.configure(text=self.text('正在下载并校验…', 'Downloading and verifying…'))
        # Network I/O runs off the UI thread; settings are captured just before shutdown.
        def fetch():
            payload = update_fetch(self.info['download_url'], UPDATE_MAX_BYTES)
            if len(payload) != self.info['size'] or hashlib.sha256(payload).hexdigest() != self.info['sha256']:
                raise ValueError('Downloaded update failed SHA-256 verification')
            validate_update_source(payload, self.info['version'])
            return payload
        self.background(fetch, 'downloaded', True)

    def poll(self):
        from tkinter import messagebox
        if self.app.closing:return
        try:
            while True:
                kind, result, manual = self.inbox.get_nowait()
                self.busy = False;self.app.update_button.state(['!disabled'])
                if kind == 'checked':
                    if result and (manual or result['version'] not in self.notified):
                        self.notified.add(result['version']);self.show_release(result)
                    elif not result and manual:
                        messagebox.showinfo('CSO2 Host Tool', self.text('当前已是最新版本。', 'You are using the latest version.'), parent=self.root)
                elif kind == 'downloaded':
                    ticket = None
                    try:
                        if not self.app.save():raise RuntimeError('Cannot save current settings')
                        ticket = prepare_host_update(self.app.path, self.info, self.app.collect_settings(), fetch=lambda *_: result)
                        update_spawn([self.app.path, '--apply-update', ticket])
                        self.app.close()
                    except Exception as error:
                        if ticket:
                            Path(ticket).with_suffix('.pyw').unlink(missing_ok=True);Path(ticket).unlink(missing_ok=True)
                        self.inbox.put(('error', str(error), True))
                elif kind == 'error':
                    if self.dialog is not None and self.dialog.winfo_exists():
                        self.download_button.state(['!disabled'])
                        self.progress.configure(text=self.text('更新失败，可重试或打开网页。', 'Update failed. Retry or open the release page.'))
                    self.app.log(self.text('检查或下载更新失败：', 'Update check or download failed: ') + result, True)
                    if manual:messagebox.showerror('CSO2 Host Tool Update', result, parent=self.root)
        except queue.Empty:
            pass
        if not self.app.closing:self.root.after(200, self.poll)



def main(path=None,settings=None):
    try:
        import argparse
        parser=argparse.ArgumentParser(add_help=False)
        parser.add_argument('--connect',action='store_true',default=True);parser.add_argument('--game-directory',default='')
        parser.add_argument('--elevated',action='store_true')
        parser.add_argument('--apply-update',default='')
        parser.add_argument('--update-ticket',default='')
        parser.add_argument('--skip-update-once',action='store_true')
        args,_=parser.parse_known_args()
        if args.apply_update:
            plan,target,*_=read_update_ticket(args.apply_update)
            if target.resolve()!=Path(path or __file__).resolve():raise ValueError('Updater target mismatch')
            apply_host_update(args.apply_update);return
        if not is_admin():
            if args.elevated:raise RuntimeError('Windows 未授予管理员权限，已停止启动，避免重复弹出授权请求')
            try:relaunch_admin(path or __file__,args.game_directory,connect=args.connect)
            except AdminLaunchCancelled:return
            return
        try:ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (OSError,AttributeError):pass
        root=tk.Tk();root.withdraw()
        app=App(root,path or __file__,settings)
        if args.game_directory:app.game_directory=args.game_directory
        if args.connect:root.after(300,lambda:app.connect_game() if app.auto_connect and not app.closing else None)
        app.reveal()
        app.updater=HostReleaseUpdater(app,automatic=not args.skip_update_once)
        if args.update_ticket:
            root.after(1500,lambda:acknowledge_host_update(args.update_ticket,path or __file__) if not app.closing else None)
        root.mainloop()
    except Exception:
        import traceback
        logfile=Path(path or __file__).with_suffix('.error.log');logfile.write_text(traceback.format_exc(),encoding='utf-8')
        ctypes.windll.user32.MessageBoxW(None,'启动失败，详情已写入：\n'+str(logfile),TITLE,0x10)



if __name__=='__main__':
    try:settings=json.loads(base64.b64decode(_PORTABLE_SETTINGS_B64))
    except (ValueError,TypeError):settings={}
    if not isinstance(settings,dict):settings={}
    main(Path(__file__).resolve(),settings)
