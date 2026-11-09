module.exports = async ({ github, context, core }) => {
  const tag = process.env.VERSION;
  const releases = await github.paginate(github.rest.repos.listReleases, {
    owner: context.repo.owner, repo: context.repo.repo, per_page: 100,
  });
  for (const release of releases) {
    if (release.tag_name === tag || release.tag_name === `v${tag}`) {
      console.log(`Deleting existing release ${release.id} for tag ${release.tag_name}`);
      await github.rest.repos.deleteRelease({
        owner: context.repo.owner, repo: context.repo.repo, release_id: release.id,
      });
    }
  }
  for (const ref of [`tags/${tag}`, `tags/v${tag}`]) {
    try {
      await github.rest.git.deleteRef({
        owner: context.repo.owner, repo: context.repo.repo, ref,
      });
      console.log(`Deleted ref ${ref}`);
    } catch (error) {
      if (error.status !== 404 && error.status !== 422) throw error;
    }
  }
};
