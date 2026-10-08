"""Publish scripts and their managed directories in one bundle release."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile
from publish_tools import gh


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('ascii')


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def version(value):
    import re
    if not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', str(value)):
        raise ValueError('Invalid version')
    return tuple(map(int, value.split('.')))


def stamp(raw, value):
    tree = ast.parse(raw.decode('utf-8-sig'))
    nodes = [n.value for n in tree.body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == 'APP_VERSION' for t in n.targets)]
    if len(nodes) != 1:
        raise ValueError('Expected one version assignment')
    node = nodes[0]; lines = raw.splitlines(keepends=True)
    a = sum(map(len, lines[:node.lineno-1])) + node.col_offset
    b = sum(map(len, lines[:node.end_lineno-1])) + node.end_col_offset
    return raw[:a] + repr(value).encode() + raw[b:]


def download_asset(asset):
    return subprocess.run(['gh', 'api', asset['url'], '-H', 'Accept: application/octet-stream'],
                          check=True, stdout=subprocess.PIPE).stdout


def discover(root, repository_id):
    tools = {}
    keys = {'APP_ID', 'APP_VERSION', 'UPDATE_REPOSITORY_ID', 'UPDATE_PROTOCOL', 'UPDATE_TAG_PREFIX', 'UPDATE_COMPONENT_DIRS'}
    for path in sorted(root.rglob('*.pyw')):
        if any(p.startswith('.') or p == 'releases' for p in path.relative_to(root).parts):
            continue
        raw = path.read_bytes(); meta = {}
        tree = ast.parse(raw.decode('utf-8-sig'))
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id in keys:
                        if t.id in meta:
                            raise ValueError('Duplicate metadata')
                        meta[t.id] = ast.literal_eval(node.value)
        if 'APP_ID' not in meta:
            continue
        product = meta['APP_ID']; version(meta['APP_VERSION'])
        if product in tools or meta['UPDATE_REPOSITORY_ID'] != repository_id or meta['UPDATE_PROTOCOL'] not in (1, 2, 3):
            raise ValueError('Invalid product metadata')
        import re
        if not re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*', product):
            raise ValueError('Invalid product identity')
        if not re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*-v', meta['UPDATE_TAG_PREFIX']):
            raise ValueError('Invalid tag prefix')
        if meta['UPDATE_PROTOCOL'] == 1:
            import base64
            values = re.findall(r'^_PORTABLE_SETTINGS_B64 = "([A-Za-z0-9+/=]*)"$', raw.decode('utf-8-sig'), re.M)
            if len(values) != 1 or json.loads(base64.b64decode(values[0])) != {}:
                raise ValueError('Clear personal HOST settings before release')
        dirs = list(meta.get('UPDATE_COMPONENT_DIRS', ())); files = {}
        if meta['UPDATE_PROTOCOL'] in (2, 3) and not dirs:
            raise ValueError('Missing dependency folders')
        for name in dirs:
            if not name or name.startswith('.') or any(c in name for c in '/\\:'):
                raise ValueError('Invalid dependency folder')
            folder = path.parent / name
            if not folder.is_dir() or folder.is_symlink():
                raise ValueError('Missing dependency folder: ' + name)
            for p in sorted(folder.rglob('*')):
                if p.is_symlink() or getattr(p.lstat(), 'st_file_attributes', 0) & 0x400:
                    raise ValueError('Dependency links are not supported')
                if p.is_file():
                    files[p.relative_to(path.parent).as_posix()] = p
        normalized = stamp(raw, '0.0.0')
        inventory = {n: dict(size=p.stat().st_size, sha256=digest(p)) for n, p in files.items()}
        inventory[product + '.pyw'] = dict(size=len(normalized), sha256=hashlib.sha256(normalized).hexdigest())
        compile(tree, str(path), 'exec')
        tools[product] = dict(path=path, raw=raw, meta=meta, files=files, dirs=dirs, source=fingerprint(inventory))
    if not tools or len({t['meta']['UPDATE_TAG_PREFIX'] for t in tools.values()}) != 1:
        raise ValueError('Missing tools or inconsistent tag prefixes')
    return tools


def publish(root, output):
    tools = discover(root, int(os.environ['TOOL_REPOSITORY_ID']))
    prefix = next(iter(tools.values()))['meta']['UPDATE_TAG_PREFIX']
    releases = []
    for page in range(1, 11):
        rows = json.loads(gh('api', f'repos/{{owner}}/{{repo}}/releases?per_page=100&page={page}').stdout)
        for row in rows:
            if not row['prerelease'] and row['tag_name'].startswith(prefix):
                try: releases.append((version(row['tag_name'][len(prefix):]), row))
                except ValueError: pass
        if len(rows) < 100: break
    number, release = max(releases, key=lambda x: x[0]) if releases else ((0, 0, 0), None)
    assets = {a['name']: a for a in (release or {}).get('assets', [])}; previous = {}
    for tool in tools.values():
        source_manifest = tool['path'].parent/'releases'/((release or {}).get('tag_name', 'none'))/(tool['meta']['APP_ID']+'.release.json')
        if source_manifest.is_file():
            item=json.loads(source_manifest.read_text(encoding='utf-8')); previous[item['product']]=item
    # Migration from the initial Release-hosted manifests.
    for asset in assets.values():
        if asset['name'].endswith('.release.json') and asset['size'] < 4*1024*1024:
            product=asset['name'][:-len('.release.json')]
            if product not in previous:
                item = json.loads(download_asset(asset)); previous[item['product']] = item
    changed = False
    for product, tool in tools.items():
        old = previous.get(product)
        if old is None: continue
        source = old.get('source_sha256')
        if source is None and old['schema'] == 1:
            raw = stamp(download_asset(assets[old['asset']]), '0.0.0')
            source = fingerprint({product + '.pyw': dict(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())})
        changed |= source != tool['source']
    requested = max(version(t['meta']['APP_VERSION']) for t in tools.values())
    chosen = max(number, requested)
    refresh_current = os.environ.get('TOOL_REFRESH_CURRENT') == '1'
    if changed and chosen <= number and not refresh_current: chosen = (number[0], number[1], number[2] + 1)
    if chosen != number: release = None; assets = {}; previous = {}
    chosen = '.'.join(map(str, chosen)); tag = prefix + chosen
    output.mkdir(parents=True, exist_ok=True); artifacts = {}; managed_paths=[]
    for product, tool in tools.items():
        meta = tool['meta']; entry = tool['path'].name if meta['UPDATE_PROTOCOL'] == 3 else product + '.pyw'; raw = stamp(tool['raw'], chosen)
        tool['path'].write_bytes(raw)
        managed_paths.append(tool['path'])
        source_folder = tool['path'].parent/'releases'/tag
        source_folder.mkdir(parents=True,exist_ok=True)
        managed_paths.append(source_folder)
        manifest = dict(schema=meta['UPDATE_PROTOCOL'], product=product, repository_id=meta['UPDATE_REPOSITORY_ID'],
                        version=chosen, source_sha256=tool['source'])
        if meta['UPDATE_PROTOCOL'] == 1:
            manifest.update(asset=entry, size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            p = output/entry; p.write_bytes(raw); artifacts[entry] = p
            old = previous.get(product)
            if old and all(old.get(k) == v for k,v in manifest.items() if k != 'source_sha256'):
                manifest = old
        elif meta['UPDATE_PROTOCOL'] == 3:
            # PYW updates preserve the local dependency folder, accounts and saves.
            # The full clean installation remains available as one Release 7Z.
            manifest.update(entry=entry, size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            (source_folder/entry).write_bytes(raw)
            # GitHub normalizes spaces in attachment names to dots.
            manual_name = tool['path'].stem.replace(' ', '.') + '.7z'
            old = previous.get(product, {}); prior = old.get('manual_archive', {})
            if (old.get('sha256') == manifest['sha256'] and old.get('source_sha256') == tool['source']
                    and manual_name in assets
                    and assets[manual_name].get('digest') == 'sha256:' + prior.get('sha256', '')):
                manifest['manual_archive'] = prior
            else:
                seven = os.environ.get('SEVEN_ZIP') or shutil.which('7z') or shutil.which('7zz')
                if not seven: raise RuntimeError('7-Zip is required')
                with tempfile.TemporaryDirectory(prefix='local-server-release-') as temp:
                    folder=Path(temp); (folder/entry).write_bytes(raw)
                    for name, p in tool['files'].items():
                        q=folder/name; q.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(p,q)
                    manual=output/manual_name
                    if manual.exists(): manual.unlink()
                    subprocess.run([seven,'a','-t7z','-mx=7','-ms=off','-mmt=2','-mtm=off','-mtc=off','-mta=off',
                                    '-bso0','-bsp0',str(manual),entry,*tool['dirs']],cwd=folder,check=True)
                manifest['manual_archive']=dict(asset=manual.name,size=manual.stat().st_size,sha256=digest(manual))
                artifacts[manual.name]=manual
        else:
            files = {n: dict(size=p.stat().st_size, sha256=digest(p)) for n,p in tool['files'].items()}
            files[entry] = dict(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            manifest.update(entry=entry, directories=tool['dirs'], files=files,
                            revision=fingerprint(dict(entry=entry, files=files)))
            archive = output/(product+'.update.zip')
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as z:
                for name in sorted(files):
                    info = zipfile.ZipInfo(name, date_time=(2026,1,1,0,0,0))
                    info.create_system=3; info.external_attr=0o100644<<16
                    z.writestr(info, raw if name == entry else tool['files'][name].read_bytes())
            manifest['archive'] = dict(asset=archive.name, size=archive.stat().st_size, sha256=digest(archive))
            shutil.copyfile(archive,source_folder/archive.name)
            manual_name = product+'.7z'; old = previous.get(product, {})
            prior = old.get('manual_archive', {})
            if (old.get('revision') == manifest['revision'] and manual_name in assets
                    and assets[manual_name].get('digest') == 'sha256:'+prior.get('sha256','')):
                manifest['manual_archive'] = prior
            else:
                seven = os.environ.get('SEVEN_ZIP') or shutil.which('7z') or shutil.which('7zz')
                if not seven: raise RuntimeError('7-Zip is required')
                with tempfile.TemporaryDirectory(prefix='bot-release-pack-') as temp:
                    folder=Path(temp); (folder/entry).write_bytes(raw)
                    for name, p in tool['files'].items():
                        q=folder/name; q.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(p,q)
                    manual=output/manual_name
                    if manual.exists(): manual.unlink()
                    subprocess.run([seven,'a','-t7z','-mx=5','-ms=off','-mmt=2','-mtm=off','-mtc=off','-mta=off',
                                    '-bso0','-bsp0',str(manual),entry,*tool['dirs']],cwd=folder,check=True)
                manifest['manual_archive']=dict(asset=manual.name,size=manual.stat().st_size,sha256=digest(manual))
                artifacts[manual.name]=manual
        metadata=output/(product+'.release.json')
        metadata.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8',newline='\n')
        shutil.copyfile(metadata,source_folder/metadata.name)
    pending=[]
    for name,path in artifacts.items():
        old=assets.get(name)
        if old:
            if old.get('digest') != 'sha256:'+digest(path):
                if not refresh_current:
                    raise ValueError('Refusing to replace a published attachment: '+name)
                pending.append(path)
        else: pending.append(path)
    if os.environ.get('TOOL_BUILD_ONLY') == '1':
        record=dict(tag=tag,version=chosen,pending=[p.name for p in pending])
        (output/'build.json').write_text(json.dumps(record,indent=2),encoding='utf-8')
        print(json.dumps(record),flush=True)
        return
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        subprocess.run(['git','config','user.name','github-actions[bot]'],check=True)
        subprocess.run(['git','config','user.email','41898282+github-actions[bot]@users.noreply.github.com'],check=True)
        subprocess.run(['git','add','--',*map(str,managed_paths)],check=True)
        if subprocess.run(['git','diff','--cached','--quiet']).returncode:
            subprocess.run(['git','commit','-m','Update bundle source manifests '+chosen+' [skip ci]'],check=True)
            subprocess.run(['git','push','origin','HEAD:'+os.environ.get('GITHUB_REF_NAME','main')],check=True)
    if not release:
        notes=output/'empty-notes.txt'; notes.write_text('',encoding='utf-8')
        target=subprocess.run(['git','rev-parse','HEAD'],check=True,text=True,stdout=subprocess.PIPE).stdout.strip()
        gh('release','create',tag,'--draft','--target',target,'--title','CSO2 Tools Bundle v'+chosen,'--notes-file',notes)
    pending.sort(key=lambda p:p.name.endswith('.release.json'))
    for path in pending:
        args=['release','upload',tag,path]
        if refresh_current: args.append('--clobber')
        gh(*args); print('Uploaded '+path.name,flush=True)
    if not release or release.get('draft'): gh('release','edit',tag,'--draft=false')
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        for name in assets:
            if name.endswith('.release.json') or name.endswith('.update.zip'):
                gh('release','delete-asset',tag,name,'--yes')
    record=dict(tag=tag,version=chosen,added=[p.name for p in pending])
    (output/'publication.json').write_text(json.dumps(record,indent=2),encoding='utf-8')
    print(json.dumps(record),flush=True)


if __name__ == '__main__':
    if os.environ.get('TOOL_BUILD_OUTPUT'):
        publish(Path.cwd(),Path(os.environ['TOOL_BUILD_OUTPUT']).resolve())
    else:
        with tempfile.TemporaryDirectory(prefix='tool-release-') as temp:
            publish(Path.cwd(),Path(temp))
