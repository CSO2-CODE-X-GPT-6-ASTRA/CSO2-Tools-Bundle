"""Refresh only BOT Tool from its already validated update archive."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile


def run(*args, **kwargs):
    return subprocess.check_output(list(map(str, args)), **kwargs)


def gh(*args):
    return run('gh', *args, '--repo', os.environ['GH_REPO'])


def api(path, *args):
    raw = run('gh', 'api', 'repos/'+os.environ['GH_REPO']+'/'+path, *args)
    return json.loads(raw) if raw.strip() else None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    import zipfile
    tag = 'host-tool-v1.0.0'
    root = Path.cwd()
    folder = root/'CSO2 Bot Tool'
    metadata = folder/'releases'/tag/'cso2-bot-tool.release.json'
    manifest = json.loads(metadata.read_text('utf8'))
    assert manifest['product'] == 'cso2-bot-tool' and manifest['version'] == '1.0.0'
    assert manifest['entry'] == 'cso2-bot-tool.pyw'
    archive = metadata.parent/'cso2-bot-tool.update.zip'
    assert digest(archive.read_bytes()) == manifest['archive']['sha256']
    assert digest((folder/manifest['entry']).read_bytes()) == manifest['files'][manifest['entry']]['sha256']
    assert run('git', 'rev-parse', 'HEAD').decode().strip() == os.environ['GITHUB_SHA']
    before = api('releases/tags/'+tag)
    old = next(a for a in before['assets'] if a['name'] == 'cso2-bot-tool.7z')
    previous_tag = api('git/ref/tags/'+tag)['object']['sha']
    notes = (root/'RELEASE.md').read_text('utf8')
    seven = shutil.which('7z') or shutil.which('7zz')
    if not seven:
        raise RuntimeError('7-Zip is required')
    with tempfile.TemporaryDirectory(prefix='bot-refresh-') as temp:
        work = Path(temp)
        stage = work/'stage'
        stage.mkdir()
        with zipfile.ZipFile(archive) as source:
            assert len(source.namelist()) == len(manifest['files'])
            assert set(source.namelist()) == set(manifest['files'])
            for name, expected in manifest['files'].items():
                path = PurePosixPath(name)
                assert not path.is_absolute() and '..' not in path.parts
                assert name == manifest['entry'] or path.parts[0] in manifest['directories']
                data = source.read(name)
                assert len(data) == expected['size'] and digest(data) == expected['sha256']
                target = stage.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        manual = work/'cso2-bot-tool.7z'
        run(seven, 'a', '-t7z', '-mx=5', '-ms=off', '-mmt=2', '-mtm=off', '-mtc=off', '-mta=off',
            '-bso0', '-bsp0', manual, manifest['entry'], *manifest['directories'], cwd=stage)
        extracted = work/'verified'
        run(seven, 'x', manual, '-o'+str(extracted), '-y', '-bso0', '-bsp0')
        actual = {p.relative_to(extracted).as_posix(): digest(p.read_bytes())
                  for p in extracted.rglob('*') if p.is_file()}
        assert actual == {n: row['sha256'] for n, row in manifest['files'].items()}
        checksum = digest(manual.read_bytes())
        staged = work/('cso2-bot-tool.'+os.environ['GITHUB_RUN_ID']+'.7z')
        shutil.copyfile(manual, staged)
        gh('release', 'upload', tag, staged)
        uploaded = next(a for a in api('releases/tags/'+tag)['assets'] if a['name'] == staged.name)
        assert uploaded['digest'] == 'sha256:'+checksum and uploaded['size'] == manual.stat().st_size
        manifest['manual_archive'] = dict(asset=manual.name, size=manual.stat().st_size, sha256=checksum)
        # OS/7-Zip versions can change archive bytes; all extracted files were
        # checked against the approved manifest before publishing its digest.
        metadata.write_bytes((json.dumps(manifest, indent=2)+'\n').replace('\n', '\r\n').encode())
        run('git', 'config', 'user.name', 'github-actions[bot]')
        run('git', 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com')
        run('git', 'add', '--', metadata)
        if subprocess.run(['git', 'diff', '--cached', '--quiet']).returncode:
            run('git', 'commit', '-m', 'Record verified BOT release archive [skip ci]')
        commit = run('git', 'rev-parse', 'HEAD').decode().strip()
        # Fail before replacement if another publisher changed the branch/tag.
        current = api('releases/tags/'+tag)
        assert current['body'] == before['body']
        assert any(a['id'] == old['id'] for a in current['assets'])
        run('git', 'push', '--atomic', 'origin', commit+':refs/heads/main', commit+':refs/tags/'+tag,
            '--force-with-lease=refs/heads/main:'+os.environ['GITHUB_SHA'],
            '--force-with-lease=refs/tags/'+tag+':'+previous_tag)
        gh('release', 'edit', tag, '--notes-file', root/'RELEASE.md')
        api('releases/assets/'+str(old['id']), '-X', 'DELETE')
        api('releases/assets/'+str(uploaded['id']), '-X', 'PATCH', '-f', 'name='+manual.name)
        after = api('releases/tags/'+tag)
        assert after['body'].replace('\r\n', '\n').strip() == notes.strip()
        assets = {a['name']: a for a in after['assets']}
        assert assets[manual.name]['digest'] == 'sha256:'+checksum
        assert old['id'] not in {a['id'] for a in after['assets']}
        for asset in before['assets']:
            if asset['id'] != old['id']:
                assert assets[asset['name']]['id'] == asset['id']
                assert assets[asset['name']]['digest'] == asset['digest']
        print(json.dumps(dict(published=True, source_sha256=manifest['files'][manifest['entry']]['sha256'],
                              archive_sha256=checksum, files_verified=len(actual), commit=commit)))


if __name__ == '__main__':
    main()
