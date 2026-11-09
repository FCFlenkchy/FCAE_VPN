module.exports = async ({ github, context, core }) => {
  const fs = require('fs');
  const path = require('path');

  const tag = process.env.FCAE_VERSION;
  const isPrerelease = process.env.FCAE_IS_PRERELEASE === 'true';
  const extraNotes = process.env.FCAE_RELEASE_NOTES;

  const parseVersion = (version) => {
    const match = /^((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2,3})(_pre-release(?:\.(?:0|[1-9][0-9]*))?)?$/.exec(version);
    if (!match) throw new Error(`Invalid release version: ${version}`);
    const nums = match[1].split('.').map(BigInt);
    while (nums.length < 4) nums.push(0n);
    const revision = match[2]?.split('.')[1];
    if (nums.some(n => n > 18446744073709551615n) || revision && BigInt(revision) > 18446744073709551615n) {
      throw new Error(`Invalid numeric version component: ${version}`);
    }
    return { nums, pre: Boolean(match[2]), revision: revision === undefined ? -1n : BigInt(revision) };
  };
  const compareVersion = (a, b) => {
    const x = parseVersion(a), y = parseVersion(b);
    const cmp = (a, b) => a < b ? -1 : a > b ? 1 : 0;
    for (let i = 0; i < 4; i++) {
      const d = cmp(x.nums[i], y.nums[i]);
      if (d) return d;
    }
    if (x.pre !== y.pre) return x.pre ? -1 : 1;
    return cmp(x.revision, y.revision);
  };

  let changelog = '';
  try {
    const notes = await github.rest.repos.generateReleaseNotes({
      owner: context.repo.owner,
      repo: context.repo.repo,
      tag_name: tag,
      target_commitish: context.sha,
    });
    changelog = notes.data.body;
  } catch (e) {
    console.log(`Could not generate release notes: ${e.message}`);
  }

  const body = (extraNotes || '').trim() ? extraNotes.trim() : changelog;

  const release = await github.rest.repos.createRelease({
    owner: context.repo.owner,
    repo: context.repo.repo,
    tag_name: tag,
    target_commitish: context.sha,
    name: `FCAE VPN ${tag}`,
    body,
    prerelease: isPrerelease,
    draft: true,
  });
  console.log(`Created release ${release.data.id} for tag ${tag} (prerelease=${isPrerelease})`);

  const dir = 'release-zips';
  for (const file of fs.readdirSync(dir)) {
    const filePath = path.join(dir, file);
    const data = fs.readFileSync(filePath);
    const ext = path.extname(file).toLowerCase();
    const contentType = ext === '.dmg' ? 'application/x-apple-diskimage'
                      : ext === '.zip' ? 'application/zip'
                      : 'application/octet-stream';
    console.log(`Uploading ${file} (${data.length} bytes, type=${contentType})...`);
    await github.rest.repos.uploadReleaseAsset({
      owner: context.repo.owner,
      repo: context.repo.repo,
      release_id: release.data.id,
      name: file,
      data,
      headers: {
        'content-type': contentType,
        'content-length': data.length,
      },
    });
  }
  console.log('All assets uploaded.');

  const published = await github.rest.repos.updateRelease({
    owner: context.repo.owner,
    repo: context.repo.repo,
    release_id: release.data.id,
    draft: false,
    make_latest: isPrerelease ? 'false' : 'legacy',
  });
  const entry = {
    version: tag,
    date: published.data.published_at.slice(0, 10),
    notes: body,
    url: published.data.html_url,
  };

  const current = await github.rest.repos.getContent({
    owner: context.repo.owner,
    repo: context.repo.repo,
    path: 'version.json',
    ref: 'main',
  });
  if (Array.isArray(current.data) || current.data.type !== 'file') {
    throw new Error('Expected version.json to be a file on main');
  }
  const previous = JSON.parse(Buffer.from(current.data.content, 'base64').toString('utf8'));
  if (!Array.isArray(previous) || !previous.length) {
    throw new Error('version.json must be a nonempty release array');
  }
  for (const release of previous) {
    parseVersion(release.version);
    if (typeof release.date !== 'string' || typeof release.notes !== 'string' || typeof release.url !== 'string') {
      throw new Error('Each release requires version, date, notes and url');
    }
  }
  const merged = previous.filter(release => compareVersion(release.version, entry.version) !== 0);
  merged.push(entry);
  const stable = [];
  const prerelease = [];
  for (const r of merged) {
    const v = parseVersion(r.version);
    if (v.pre) prerelease.push(r); else stable.push(r);
  }
  stable.sort((a, b) => compareVersion(b.version, a.version));
  prerelease.sort((a, b) => compareVersion(b.version, a.version));
  const next = [];
  if (stable.length) next.push(stable[0]);
  if (prerelease.length) next.push(prerelease[0]);
  next.sort((a, b) => Number(parseVersion(a.version).pre) - Number(parseVersion(b.version).pre)
    || compareVersion(b.version, a.version));
  const content = `${JSON.stringify(next, null, 2)}\n`;
  if (content !== Buffer.from(current.data.content, 'base64').toString('utf8')) {
    await github.rest.repos.createOrUpdateFileContents({
      owner: context.repo.owner,
      repo: context.repo.repo,
      path: 'version.json',
      branch: 'main',
      sha: current.data.sha,
      message: `chore: bump version.json ${isPrerelease ? 'pre-release to' : 'to'} ${entry.version}`,
      content: Buffer.from(content, 'utf8').toString('base64'),
    });
    console.log(`Committed version.json for ${entry.version} after release uploads`);
  } else {
    console.log('version.json already matches this release');
  }
};
