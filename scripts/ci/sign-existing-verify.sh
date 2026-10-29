#!/usr/bin/env bash
# Verify the requested run and artifact for sign-existing.yml (moved out of the workflow so its run script stays under the actionlint size limit).
set -euo pipefail
fail() { echo "sign-existing refused: $*" >&2; exit 1; }
command -v jq >/dev/null || fail "jq is not available on this runner"
[[ "$INPUT_RUN_ID" =~ ^[1-9][0-9]{0,19}$ ]] || fail "run_id must be a numeric workflow run id"
[[ "$INPUT_ARTIFACT" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || fail "artifact must be a numeric artifact id or a plain artifact name"
[[ "$INPUT_SOURCE_SHA" =~ ^[0-9a-f]{7,40}$ ]] || fail "source_sha must be 7 to 40 lowercase hexadecimal characters"
run_json="$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$INPUT_RUN_ID")"
run_id="$(jq -r '.id' <<<"$run_json")"
run_repo="$(jq -r '.repository.full_name' <<<"$run_json")"
run_repo_id="$(jq -r '.repository.id' <<<"$run_json")"
head_repo="$(jq -r '.head_repository.full_name // empty' <<<"$run_json")"
head_repo_id="$(jq -r '.head_repository.id // empty' <<<"$run_json")"
head_sha="$(jq -r '.head_sha' <<<"$run_json")"
status="$(jq -r '.status' <<<"$run_json")"
conclusion="$(jq -r '.conclusion // empty' <<<"$run_json")"
[ "$run_id" = "$INPUT_RUN_ID" ] || fail "run id mismatch"
[ "$run_repo" = "$GITHUB_REPOSITORY" ] || fail "run $INPUT_RUN_ID belongs to $run_repo, not $GITHUB_REPOSITORY"
[ "$head_repo" = "$GITHUB_REPOSITORY" ] && [ "$head_repo_id" = "$run_repo_id" ] || fail "run $INPUT_RUN_ID was built from another repository or a fork"
[ "$status" = completed ] && [ "$conclusion" = success ] || fail "run $INPUT_RUN_ID is $status/$conclusion, not a successful completed run"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail "run head sha is not a full commit sha"
case "$head_sha" in "$INPUT_SOURCE_SHA"*) ;; *) fail "run $INPUT_RUN_ID head sha $head_sha does not start with source_sha $INPUT_SOURCE_SHA" ;; esac
artifacts_json="$(gh api --paginate "repos/$GITHUB_REPOSITORY/actions/runs/$INPUT_RUN_ID/artifacts?per_page=100" | jq -s '[.[].artifacts[]]')"
if [[ "$INPUT_ARTIFACT" =~ ^[0-9]+$ ]]; then
  picked="$(jq -c --argjson id "$INPUT_ARTIFACT" '[.[] | select(.id == $id)]' <<<"$artifacts_json")"
else
  picked="$(jq -c --arg name "$INPUT_ARTIFACT" '[.[] | select(.name == $name)]' <<<"$artifacts_json")"
fi
[ "$(jq 'length' <<<"$picked")" = 1 ] || fail "artifact $INPUT_ARTIFACT is not exactly one artifact of run $INPUT_RUN_ID"
artifact_id="$(jq -r '.[0].id' <<<"$picked")"
artifact_name="$(jq -r '.[0].name' <<<"$picked")"
[ "$(jq -r '.[0].expired' <<<"$picked")" = false ] || fail "artifact $artifact_name has expired"
[ "$(jq -r '.[0].workflow_run.id' <<<"$picked")" = "$INPUT_RUN_ID" ] || fail "artifact $artifact_name belongs to another run"
[ "$(jq -r '.[0].workflow_run.head_sha' <<<"$picked")" = "$head_sha" ] || fail "artifact $artifact_name was built from another commit"
[ "$(jq -r '.[0].workflow_run.head_repository_id' <<<"$picked")" = "$run_repo_id" ] || fail "artifact $artifact_name was built from another repository"
[[ "$artifact_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || fail "artifact name is not a plain name"
git cat-file -e "$head_sha^{commit}" 2>/dev/null || fail "source commit $head_sha is not in this repository's history"
git merge-base --is-ancestor "$head_sha" "$GITHUB_SHA" || fail "source commit $head_sha is not an ancestor of the signing revision $GITHUB_SHA"
mkdir -p "$RUNNER_TEMP/dev-signed"
jq -n --arg repo "$GITHUB_REPOSITORY" --arg run "$run_id" --argjson artifactId "$artifact_id" --arg artifactName "$artifact_name" --arg sourceSha "$head_sha" --arg requested "$INPUT_SOURCE_SHA" --arg signingRevision "$GITHUB_SHA" '{schema: 1, repository: $repo, runId: $run, artifactId: $artifactId, artifactName: $artifactName, sourceSha: $sourceSha, requestedSourceSha: $requested, signingRevision: $signingRevision}' > "$RUNNER_TEMP/dev-signed/source-verification.json"
{
  printf 'run_id=%s\n' "$run_id"
  printf 'artifact_id=%s\n' "$artifact_id"
  printf 'artifact_name=%s\n' "$artifact_name"
  printf 'head_sha=%s\n' "$head_sha"
} >> "$GITHUB_OUTPUT"
