module.exports = async ({ github, context, core }) => {
  const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
  const prefixes = ['cmake-', 'gradle-', 'sccache-', 'glfw-'];

  for (const prefix of prefixes) {
    let page = 1;
    let totalDeleted = 0;
    while (true) {
      const res = await github.rest.actions.getActionsCacheList({
        owner: context.repo.owner,
        repo: context.repo.repo,
        key: prefix,
        per_page: 100,
        page,
      });
      const caches = res.data.actions_caches || [];
      if (caches.length === 0) break;

      const old = caches.filter(c => new Date(c.created_at).getTime() < oneDayAgo);
      const recent = caches.filter(c => new Date(c.created_at).getTime() >= oneDayAgo);
      const excess = recent.slice(3);
      const toDelete = [...old, ...excess];

      for (const cache of toDelete) {
        try {
          await github.rest.actions.deleteActionsCacheById({
            owner: context.repo.owner,
            repo: context.repo.repo,
            cache_id: cache.id,
          });
          totalDeleted++;
          console.log(`Deleted: ${cache.key} (created ${cache.created_at})`);
        } catch (e) {
          console.log(`Skipped ${cache.key}: ${e.message}`);
        }
      }
      if (caches.length < 100) break;
      page++;
    }
    console.log(`Cleaned ${totalDeleted} caches for prefix '${prefix}'`);
  }
};
