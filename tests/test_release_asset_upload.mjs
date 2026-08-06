import assert from "node:assert/strict"
import { chmod, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { spawnSync } from "node:child_process"
import test from "node:test"

const repositoryRoot = new URL("..", import.meta.url).pathname
const script = join(repositoryRoot, "scripts/upload_github_release_assets.sh")

async function runUpload(status, body, expectedOutput) {
  const directory = await mkdtemp(join(tmpdir(), "kenning-release-assets-"))
  const binDirectory = join(directory, "bin")
  const asset = join(directory, "release-manifest.json")
  const fakeCurl = join(binDirectory, "curl")
  await mkdir(binDirectory)
  await writeFile(asset, "{}\n")
  await writeFile(join(directory, "response.json"), body)
  await writeFile(fakeCurl, `#!/usr/bin/env bash
output=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --write-out) shift 2 ;;
    *) shift ;;
  esac
done
cp "$FAKE_RESPONSE" "$output"
printf '%s' "$FAKE_STATUS"
`)
  await chmod(fakeCurl, 0o755)
  try {
    const result = spawnSync("bash", [script, asset], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${binDirectory}:${process.env.PATH}`,
        FAKE_RESPONSE: join(directory, "response.json"),
        FAKE_STATUS: String(status),
        GITHUB_RELEASE_UPLOAD_URL: "https://uploads.example.test/assets",
        GITHUB_RELEASE_TOKEN: "test-token",
      },
    })
    assert.equal(result.status, 0, result.stderr)
    assert.match(`${result.stdout}${result.stderr}`, expectedOutput)
    return result
  } finally {
    await rm(directory, { force: true, recursive: true })
  }
}

test("reports a verified successful asset upload", async () => {
  const result = await runUpload(201, '{"name":"release-manifest.json"}\n', /uploaded asset: release-manifest\.json/)
  assert.doesNotMatch(result.stderr, /WARNING: failed to upload/)
})

test("reports HTTP failures without failing deployment", async () => {
  const result = await runUpload(422, '{"message":"validation failed"}\n', /WARNING: failed to upload asset release-manifest\.json \(HTTP 422; non-fatal\)/)
  assert.doesNotMatch(result.stdout, /uploaded asset:/)
})

test("reports malformed success responses without claiming success", async () => {
  const result = await runUpload(201, '{"message":"missing asset name"}\n', /WARNING: failed to upload asset release-manifest\.json \(HTTP 201; non-fatal\)/)
  assert.doesNotMatch(result.stdout, /uploaded asset:/)
})
