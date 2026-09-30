const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function releaseVersion(tag) {
  // Strict SemVer without build metadata; numeric prerelease identifiers cannot have leading zeroes.
  const number = '(0|[1-9][0-9]*)';
  const identifier = '(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)';
  const pattern = new RegExp(`^v${number}\\.${number}\\.${number}(?:-(${identifier}(?:\\.${identifier})*))?$`);
  if (!pattern.test(tag)) throw new Error(`Invalid release tag: ${tag}; expected vMAJOR.MINOR.PATCH[-PRERELEASE]`);
  return { tag, prerelease: tag.includes('-') };
}

async function publish({ github, context, core, directory = 'release' }) {
  const { tag, prerelease } = releaseVersion(context.ref.replace(/^refs\/tags\//, ''));
  const repo = context.repo;
  // Resolve the tag again immediately before publishing, including annotated tags.
  const { data: commit } = await github.rest.repos.getCommit({ ...repo, ref: tag });
  if (commit.sha !== context.sha) throw new Error('Release tag moved since this build started');
  const marker = `<!-- release-commit: ${context.sha} -->`;
  const names = [`huawei-pc-manager-bootstrap-${tag}.zip`, 'SHA256SUMS.txt'];
  const files = names.map(name => ({ name, data: fs.readFileSync(path.join(directory, name)) }));
  const digest = crypto.createHash('sha256').update(files[0].data).digest('hex');
  if (files[1].data.toString('utf8') !== `${digest}  ${names[0]}\n`) throw new Error('Release checksum mismatch');
  let release;
  try {
    ({ data: release } = await github.rest.repos.getReleaseByTag({ ...repo, tag }));
  } catch (error) {
    if (error.status !== 404) throw error;
  }
  if (release) {
    if (!release.body?.includes(marker)) throw new Error('Existing release is not owned by this commit; refusing to overwrite it');
    if (!release.draft) {
      const assets = await github.paginate(github.rest.repos.listReleaseAssets, { ...repo, release_id: release.id });
      if (!names.every(name => assets.some(asset => asset.name === name && asset.state === 'uploaded' && asset.size > 0))) {
        throw new Error('Published release is incomplete; repair manually or publish a new version');
      }
      core.info(`Release ${tag} is already published; leaving its assets unchanged`);
      return;
    }
  } else {
    const { data: notes } = await github.rest.repos.generateReleaseNotes({ ...repo, tag_name: tag, target_commitish: context.sha });
    ({ data: release } = await github.rest.repos.createRelease({
      ...repo, tag_name: tag, target_commitish: context.sha,
      name: `华为电脑管家安装器 ${tag}`, draft: true, prerelease,
      body: `${marker}\n\n${notes.body}\n\n下载 ZIP 并完整解压，EXE 与核心 DLL 必须放在同一目录。SHA256SUMS.txt 可用于校验 ZIP。\n`,
    }));
  }
  // A failed upload leaves a draft. Only drafts created for this exact commit may be repaired.
  const assets = await github.paginate(github.rest.repos.listReleaseAssets, { ...repo, release_id: release.id });
  for (const file of files) {
    for (const asset of assets.filter(asset => asset.name === file.name)) {
      await github.rest.repos.deleteReleaseAsset({ ...repo, asset_id: asset.id });
    }
    await github.rest.repos.uploadReleaseAsset({ ...repo, release_id: release.id, name: file.name, data: file.data });
  }
  await github.rest.repos.updateRelease({ ...repo, release_id: release.id, draft: false, prerelease, make_latest: 'legacy' });
  core.info(`Published ${tag}`);
}

module.exports = { releaseVersion, publish };
