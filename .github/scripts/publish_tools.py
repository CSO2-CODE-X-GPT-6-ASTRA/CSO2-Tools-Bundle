"""Discover tools by literal metadata and attach them to one bundle release.

Filenames and repository URLs are deliberately not used as product identities.
All tools in a bundle share APP_VERSION and UPDATE_TAG_PREFIX, with distinct APP_IDs.
New tools can be added to the current release without changing its description.
Existing versioned payloads are never replaced with different contents.
"""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def gh(*args, check=True):
    return subprocess.run(['gh', *map(str, args)], check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def discover(root, repository_id):
    found = {}
    keys = {'APP_ID', 'APP_VERSION', 'UPDATE_REPOSITORY_ID', 'UPDATE_PROTOCOL', 'UPDATE_TAG_PREFIX'}
    for path in sorted(root.rglob('*.pyw')):
        if any(part.startswith('.') for part in path.relative_to(root).parts):
            continue
        raw = path.read_bytes()
        tree = ast.parse(raw.decode('utf-8-sig'), filename=str(path))
        meta = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in keys:
                        if target.id in meta:
                            raise ValueError(f'Duplicate metadata {target.id}: {path}')
                        meta[target.id] = ast.literal_eval(node.value)
        if 'APP_ID' not in meta:
            continue
        if set(meta) != keys or meta['UPDATE_PROTOCOL'] != 1 or meta['UPDATE_REPOSITORY_ID'] != repository_id:
            raise ValueError(f'Incomplete or incompatible update metadata: {path}')
        product, version, prefix = meta['APP_ID'], meta['APP_VERSION'], meta['UPDATE_TAG_PREFIX']
        if not re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*', product):
            raise ValueError(f'Invalid product ID: {path}')
        if not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', version):
            raise ValueError(f'Invalid semantic version: {path}')
        if not re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*-v', prefix):
            raise ValueError(f'Invalid release tag prefix: {path}')
        if product in found:
            raise ValueError(f'A product appears more than once: {product}')
        settings = re.findall(r'^_PORTABLE_SETTINGS_B64 = "([A-Za-z0-9+/=]*)"$', raw.decode('utf-8-sig'), re.M)
        if len(settings) != 1 or json.loads(base64.b64decode(settings[0])) != {}:
            raise ValueError(f'Clear embedded personal settings before publishing: {path}')
        compile(tree, str(path), 'exec')
        # ASCII asset names follow product identity, not source filename.
        asset = product + '.pyw'
        manifest = dict(schema=1, product=product, repository_id=repository_id, version=version,
                        asset=asset, size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        found[product] = dict(path=path, raw=raw, manifest=manifest, tag=prefix+version, tag_prefix=prefix)
    if not found:
        raise ValueError('No versioned tool scripts were found')
    return found


def publish_bundle(tools):
    tools = list(tools)
    tags = {tool['tag'] for tool in tools}
    if len(tags) != 1:
        raise ValueError('Bundle tools must share APP_VERSION and UPDATE_TAG_PREFIX')
    tag = tags.pop()
    existing = gh('api', f'repos/{{owner}}/{{repo}}/releases/tags/{tag}', check=False)
    release = json.loads(existing.stdout) if existing.returncode == 0 else None
    if not release and '404' not in existing.stderr:
        raise RuntimeError(existing.stderr)
    assets = {asset['name']: asset for asset in (release or {}).get('assets', [])}
    pending = []
    for tool in tools:
        manifest = tool['manifest'];product = manifest['product']
        metadata_name = product + '.release.json'
        metadata_bytes = (json.dumps(manifest, indent=2)+'\n').encode('utf-8')
        # Check every existing payload before making any changes to the release.
        for name, payload in ((manifest['asset'], tool['raw']), (metadata_name, metadata_bytes)):
            asset = assets.get(name)
            if asset:
                if asset.get('digest') != 'sha256:' + hashlib.sha256(payload).hexdigest():
                    raise ValueError(f'{tag}: {name} already has different contents. Increase the bundle version.')
            else:
                pending.append((name, payload))
    if not pending and release and not release.get('draft'):
        print(f'{tag}: all bundle attachments already match')
        return
    with tempfile.TemporaryDirectory(prefix='tool-release-') as temporary:
        folder = Path(temporary)
        if not release:
            notes_path = folder / 'empty-notes.txt';notes_path.write_text('', encoding='utf-8')
            gh('release', 'create', tag, '--draft', '--target', os.environ['GITHUB_SHA'],
               '--title', 'CSO2 Tools Bundle v' + tools[0]['manifest']['version'], '--notes-file', notes_path)
        for name, payload in pending:
            path = folder / name;path.write_bytes(payload)
            gh('release', 'upload', tag, path)
        # Existing descriptions are maintained by the user, never by this script.
        if not release or release.get('draft'):
            gh('release', 'edit', tag, '--draft=false')
        print(f'{tag}: added {len(pending)} bundle attachments')


def main():
    publish_bundle(discover(Path.cwd(), int(os.environ['TOOL_REPOSITORY_ID'])).values())


if __name__ == '__main__':
    main()
