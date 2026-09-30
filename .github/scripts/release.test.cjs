const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { releaseVersion, publish } = require('./release.cjs');

test('strict release and prerelease tags', () => {
  for (const tag of ['v0.1.12', 'v1.0.0', 'v2.3.4-rc.1', 'v2.3.4-beta', 'v2.3.4-0']) {
    assert.equal(releaseVersion(tag).prerelease, tag.includes('-'));
  }
  for (const tag of ['v1', 'v01.2.3', 'v1.2.3-01', 'v1.2.3-', 'v1.2.3+build', 'v1.2.3/evil', '1.2.3']) {
    assert.throws(() => releaseVersion(tag));
  }
});

function fixture(t, existing, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'release-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const tag = options.tag || 'v0.1.12';
  const sha = 'a'.repeat(40);
  const name = `huawei-pc-manager-bootstrap-${tag}.zip`;
  const data = Buffer.from('fixture archive');
  const digest = crypto.createHash('sha256').update(data).digest('hex');
  fs.writeFileSync(path.join(directory, name), data);
  fs.writeFileSync(path.join(directory, 'SHA256SUMS.txt'), `${digest}  ${name}\n`);
  const calls = [];
  let assets = options.assets || [];
  const repos = {
    getCommit: async () => ({ data: { sha: options.moved ? 'b'.repeat(40) : sha } }),
    getReleaseByTag: async () => { if (!existing) throw { status: options.status || 404 }; return { data: existing }; },
    generateReleaseNotes: async () => ({ data: { body: 'Changes' } }),
    createRelease: async args => { calls.push(['create', args]); return { data: { id: 1 } }; },
    listReleaseAssets: async () => assets,
    deleteReleaseAsset: async args => { calls.push(['delete', args]); },
    uploadReleaseAsset: async args => { calls.push(['upload', args]); if (options.failUpload) throw Error('upload failed'); },
    updateRelease: async args => { calls.push(['publish', args]); },
  };
  return { calls, directory, args: { directory, github: { rest: { repos }, paginate: fn => fn() }, context: { ref: `refs/tags/${tag}`, sha, repo: { owner: 'test', repo: 'test' } }, core: { info() {} } } };
}
const marker = `<!-- release-commit: ${'a'.repeat(40)} -->`;

test('create draft, upload both files, publish last', async t => {
  const f = fixture(t);
  await publish(f.args);
  assert.deepEqual(f.calls.map(c => c[0]), ['create', 'upload', 'upload', 'publish']);
  assert.equal(f.calls[0][1].draft, true);
  assert.equal(f.calls.at(-1)[1].draft, false);
  assert.equal(f.calls.at(-1)[1].prerelease, false);
});
test('prerelease classification', async t => {
  const f = fixture(t, null, { tag: 'v0.1.12-rc.1' });
  await publish(f.args);
  assert.equal(f.calls.at(-1)[1].prerelease, true);
});
test('resume own draft and replace partial assets', async t => {
  const f = fixture(t, { id: 1, body: marker, draft: true }, { assets: [{ id: 7, name: 'SHA256SUMS.txt' }] });
  await publish(f.args);
  assert.deepEqual(f.calls.map(c => c[0]), ['upload', 'delete', 'upload', 'publish']);
});
test('already published release is an unchanged successful no-op', async t => {
  const f = fixture(t, { id: 1, body: marker, draft: false }, { assets: ['huawei-pc-manager-bootstrap-v0.1.12.zip', 'SHA256SUMS.txt'].map(name => ({ name, state: 'uploaded', size: 10 })) });
  await publish(f.args);
  assert.deepEqual(f.calls, []);
});
test('refuse unrelated or incomplete published releases', async t => {
  for (const existing of [{ id: 1, body: 'manual release', draft: true }, { id: 1, body: marker, draft: false }]) {
    const f = fixture(t, existing);
    await assert.rejects(publish(f.args));
    assert.deepEqual(f.calls, []);
  }
});
test('upload failure never publishes', async t => {
  const f = fixture(t, null, { failUpload: true });
  await assert.rejects(publish(f.args), /upload failed/);
  assert.ok(!f.calls.some(c => c[0] === 'publish'));
});
test('moved tags and API failures cannot create releases', async t => {
  for (const options of [{ moved: true }, { status: 403 }]) {
    const f = fixture(t, null, options);
    await assert.rejects(publish(f.args));
    assert.deepEqual(f.calls, []);
  }
});
test('bad checksums cannot create releases', async t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.directory, 'SHA256SUMS.txt'), 'bad hash');
  await assert.rejects(publish(f.args), /checksum mismatch/);
  assert.deepEqual(f.calls, []);
});
