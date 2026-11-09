module.exports = async ({ github, context, core }) => {
  const raw = process.env.RELEASE_VERSION.trim();
  const pre = process.env.PRERELEASE === 'true';
  const match = /^[vV]?((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2,3})(_pre-release(?:\.(?:0|[1-9][0-9]*))?)?$/.exec(raw);
  if (!match) throw new Error('Use a version such as 1.4.0 or 1.4.0_pre-release');
  if (match[1].split('.').some(n => BigInt(n) > 65535n)) {
    throw new Error('Numeric version components must fit Windows version resources (0..65535)');
  }
  if (!pre && match[2]) throw new Error('Select the prerelease option for a _pre-release version');
  const revision = match[2]?.split('.')[1];
  if (revision && BigInt(revision) > 18446744073709551615n) {
    throw new Error('Prerelease revision is too large');
  }
  const versionClean = match[1];
  const versionFull = `${match[1]}${pre ? match[2] || '_pre-release' : ''}`;
  core.setOutput('version', versionClean);
  core.setOutput('version_full', versionFull);
  core.setOutput('is_prerelease', pre ? 'true' : 'false');
  core.setOutput('macos_version', match[1].split('.').slice(0, 3).join('.'));
  core.info(`Release version: ${versionClean} (full: ${versionFull}, prerelease: ${pre})`);
};
