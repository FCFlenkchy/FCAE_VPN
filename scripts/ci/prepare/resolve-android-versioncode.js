module.exports = async ({ github, context, core }) => {
  const { data } = await github.rest.actions.listWorkflowRuns({
    owner: context.repo.owner,
    repo: context.repo.repo,
    workflow_id: 'build_all.yml',
    status: 'success',
    created: '>=2026-10-02T05:10:00Z',
    per_page: 1,
  });
  const code = data.total_count + 2;
  core.setOutput('version_code', String(code));
  core.info(`Android versionCode: ${code}`);
};
