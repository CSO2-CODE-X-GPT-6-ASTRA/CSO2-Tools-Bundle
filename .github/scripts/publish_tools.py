"""Discover tools by literal metadata and publish one versioned release per product.

Filenames and repository URLs are deliberately not used as product identities.
Bump APP_VERSION in a changed script before pushing. Existing release assets are
immutable: a different payload under an existing version fails instead of replacing it.
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
        if product in found or any(row['tag_prefix'] == prefix for row in found.values()):
            raise ValueError(f'A product or release tag prefix appears more than once: {product}')
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


def publish(tool):
    manifest = tool['manifest'];tag = tool['tag'];product = manifest['product']
    existing = gh('api', f'repos/{{owner}}/{{repo}}/releases/tags/{tag}', check=False)
    release = json.loads(existing.stdout) if existing.returncode == 0 else None
    if release:
        assets = [a for a in release.get('assets', []) if a['name'] == manifest['asset']]
        metadata = [a for a in release.get('assets', []) if a['name'] == product + '.release.json']
        if assets and assets[0].get('digest') == 'sha256:' + manifest['sha256'] and metadata and not release.get('draft'):
            print(f'{tag}: already published with the same SHA-256')
            return
        if not release.get('draft'):
            raise ValueError(f'{tag} already exists with different contents. Increase APP_VERSION before publishing.')
    elif '404' not in existing.stderr:
        raise RuntimeError(existing.stderr)
    title = ('CSO2 Host Tool' if product == 'cso2-host-tool' else product) + ' v' + manifest['version']
    notes = (f'{title}\n\n'
             'Download the .pyw attachment and run it with Python 3.10+ on Windows (tkinter required).\n\n'
             'HOST TOOL checks its own releases automatically. Updates preserve local settings, '
             'keep the previous file as .OLD during restart, and remove it only after successful startup. '
             'You can also open the release page and update manually.\n\n'
             'The JSON attachment supplies the product identity, version, filename and SHA-256 checksum '
             'used by the updater. Repository and attachment names are discovered dynamically.\n\n'
             'Initial release validation: 15 update regression checks and GUI startup checks passed. '
             'Game interaction has not been verified in a live game as part of this release.\n')
    if manifest['version'] != '1.0.0' or product != 'cso2-host-tool':
        notes = (f'{title}\n\nDownload the .pyw attachment. '
                 'The JSON attachment contains product metadata and a SHA-256 checksum.\n')
    with tempfile.TemporaryDirectory(prefix='tool-release-') as temporary:
        folder = Path(temporary)
        asset_path = folder / manifest['asset'];asset_path.write_bytes(tool['raw'])
        manifest_path = folder / (product + '.release.json')
        manifest_path.write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
        notes_path = folder / 'release-notes.md';notes_path.write_text(notes, encoding='utf-8')
        if not release:
            gh('release', 'create', tag, '--draft', '--target', os.environ['GITHUB_SHA'],
               '--title', title, '--notes-file', notes_path)
        gh('release', 'upload', tag, asset_path, manifest_path, '--clobber')
        # Publishing happens only once both complete attachments are uploaded.
        gh('release', 'edit', tag, '--draft=false', '--title', title, '--notes-file', notes_path)
        print(f'Published {tag}: {manifest["sha256"]}')


def main():
    for tool in discover(Path.cwd(), int(os.environ['TOOL_REPOSITORY_ID'])).values():
        publish(tool)


if __name__ == '__main__':
    main()
