"""Refresh the verified HOST attachment without rebuilding other tools."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from publish_bundle import fingerprint, stamp


def run(*args):
    return subprocess.check_output(list(map(str, args)))


def gh(*args):
    return run('gh', *args, '--repo', os.environ['GH_REPO'])


def api(path, *args):
    raw = run('gh', 'api', 'repos/' + os.environ['GH_REPO'] + '/' + path, *args)
    return json.loads(raw) if raw.strip() else None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def signature(asset):
    return {key: asset[key] for key in ('id', 'name', 'size', 'digest')}


def main():
    root = Path.cwd()
    tag = 'host-tool-v1.0.0'
    name = 'cso2-host-tool.pyw'
    source = root / 'CSO2 Host Tool' / name
    manifest = json.loads((source.parent / 'releases' / tag / 'cso2-host-tool.release.json').read_text('utf8'))
    raw = source.read_bytes()
    tree = ast.parse(raw.decode('utf8'))
    compile(tree, str(source), 'exec')
    settings = [ast.literal_eval(node.value) for node in tree.body
                if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == '_PORTABLE_SETTINGS_B64' for t in node.targets)]
    assert settings == ['e30='], 'HOST release settings must be empty'
    metadata = {t.id: ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                for t in node.targets if isinstance(t, ast.Name)
                and t.id in {'APP_ID', 'APP_VERSION', 'UPDATE_REPOSITORY_ID', 'UPDATE_PROTOCOL', 'UPDATE_TAG_PREFIX'}}
    assert metadata == dict(APP_ID='cso2-host-tool', APP_VERSION='1.0.0', UPDATE_REPOSITORY_ID=1410625177,
                            UPDATE_PROTOCOL=1, UPDATE_TAG_PREFIX='host-tool-v')
    normalized = stamp(raw, '0.0.0')
    assert manifest == dict(schema=1, product='cso2-host-tool', repository_id=1410625177, version='1.0.0',
                            source_sha256=fingerprint({name: dict(size=len(normalized), sha256=digest(normalized))}),
                            asset=name, size=len(raw), sha256=digest(raw))
    commit = run('git', 'rev-parse', 'HEAD').decode().strip()
    assert commit == os.environ['GITHUB_SHA']
    before = api('releases/tags/' + tag)
    assert not before['draft'] and not before.get('immutable', False)
    old = next(a for a in before['assets'] if a['name'] == name)
    others = sorted((signature(a) for a in before['assets'] if a['id'] != old['id']), key=lambda a: a['id'])
    old_tag = api('git/ref/tags/' + tag)['object']['sha']
    notes = (root / 'RELEASE.md').read_text('utf8')
    staged_name = 'cso2-host-tool.' + os.environ['GITHUB_RUN_ID'] + '.' + os.environ.get('GITHUB_RUN_ATTEMPT', '1') + '.pyw'
    previous_name = 'cso2-host-tool.previous-' + str(old['id']) + '.pyw'

    def check_asset(asset):
        assert asset['size'] == len(raw) and asset['digest'] == 'sha256:' + digest(raw)
        downloaded = run('gh', 'api', 'repos/' + os.environ['GH_REPO'] + '/releases/assets/' + str(asset['id']),
                         '-H', 'Accept: application/octet-stream')
        assert downloaded == raw, 'Downloaded HOST attachment differs from source'

    with tempfile.TemporaryDirectory(prefix='host-refresh-') as folder:
        staged = Path(folder) / staged_name
        staged.write_bytes(raw)
        gh('release', 'upload', tag, staged)
        current = api('releases/tags/' + tag)
        uploaded = next(a for a in current['assets'] if a['name'] == staged_name)
        check_asset(uploaded)
        assert signature(next(a for a in current['assets'] if a['id'] == old['id'])) == signature(old)
        assert sorted((signature(a) for a in current['assets'] if a['id'] not in (old['id'], uploaded['id'])),
                      key=lambda a: a['id']) == others
        assert api('git/ref/heads/main')['object']['sha'] == commit, 'Main changed during publication'
        run('git', 'push', 'origin', commit + ':refs/tags/' + tag,
            '--force-with-lease=refs/tags/' + tag + ':' + old_tag)
        api('releases/assets/' + str(old['id']), '-X', 'PATCH', '-f', 'name=' + previous_name)
        try:
            api('releases/assets/' + str(uploaded['id']), '-X', 'PATCH', '-f', 'name=' + name)
            gh('release', 'edit', tag, '--notes-file', root / 'RELEASE.md')
            after = api('releases/tags/' + tag)
            check_asset(next(a for a in after['assets'] if a['name'] == name))
            assert after['body'].replace('\r\n', '\n').strip() == notes.strip()
        except Exception:
            current = api('releases/tags/' + tag)
            if any(a['id'] == uploaded['id'] and a['name'] == name for a in current['assets']):
                api('releases/assets/' + str(uploaded['id']), '-X', 'PATCH', '-f', 'name=' + staged_name)
            api('releases/assets/' + str(old['id']), '-X', 'PATCH', '-f', 'name=' + name)
            raise
        api('releases/assets/' + str(old['id']), '-X', 'DELETE')
        final = api('releases/tags/' + tag)
        assert sorted((signature(a) for a in final['assets'] if a['id'] != uploaded['id']),
                      key=lambda a: a['id']) == others
        assert api('git/ref/tags/' + tag)['object']['sha'] == commit
        print(json.dumps(dict(published=True, commit=commit, sha256=digest(raw), size=len(raw),
                              download_verified=True, other_assets_unchanged=True)))


if __name__ == '__main__':
    main()
