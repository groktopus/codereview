import {createHash} from 'node:crypto'
import {constants} from 'node:fs'
import {readFileSync, lstatSync, openSync, fstatSync, closeSync, writeFileSync} from 'node:fs'
import path from 'node:path'
import {DefaultArtifactClient} from '@actions/artifact'

const MAX_INPUT_BYTES = 128 * 1024
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/

function fail() {
  const resultPath = process.env.PR_REVIEW_UPLOAD_RESULT
  if (resultPath && path.isAbsolute(resultPath)) {
    try {
      writeFileSync(resultPath, JSON.stringify({status: 'UNAVAILABLE', reason: 'artifact_upload_failed'}), {flag: 'wx', mode: 0o600})
    } catch {}
  }
  process.exitCode = 1
}

async function main() {
  const inputPath = process.env.PR_REVIEW_UPLOAD_INPUT
  if (!inputPath || !path.isAbsolute(inputPath)) return fail()
  const inputStat = lstatSync(inputPath)
  if (!inputStat.isFile() || inputStat.size > 2048) return fail()
  const inputFd = openSync(inputPath, constants.O_RDONLY | (constants.O_NOFOLLOW || 0))
  const inputOpened = fstatSync(inputFd)
  if (!inputOpened.isFile() || inputOpened.size > 2048) {
    closeSync(inputFd)
    return fail()
  }
  const input = JSON.parse(readFileSync(inputFd, 'utf8'))
  closeSync(inputFd)
  const runId = Number(process.env.GITHUB_RUN_ID)
  const runAttempt = Number(process.env.GITHUB_RUN_ATTEMPT)
  if (
    !Number.isSafeInteger(runId) || runId < 1 || runId !== input.run_id ||
    !Number.isSafeInteger(runAttempt) || runAttempt < 1 ||
    typeof input.name !== 'string' || !NAME_PATTERN.test(input.name) ||
    typeof input.filename !== 'string' || !NAME_PATTERN.test(input.filename) ||
    typeof input.content_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(input.content_sha256) ||
    !Number.isSafeInteger(input.content_bytes) || input.content_bytes < 0 || input.content_bytes > MAX_INPUT_BYTES
  ) return fail()

  if (typeof input.content_file !== 'string' || input.content_file !== input.filename) return fail()
  const contentPath = path.resolve(path.dirname(inputPath), input.content_file)
  if (path.dirname(contentPath) !== path.dirname(path.resolve(inputPath))) return fail()
  const contentStat = lstatSync(contentPath)
  if (!contentStat.isFile() || contentStat.size !== input.content_bytes || contentStat.size > MAX_INPUT_BYTES) return fail()
  const contentFd = openSync(contentPath, constants.O_RDONLY | (constants.O_NOFOLLOW || 0))
  const contentOpened = fstatSync(contentFd)
  if (!contentOpened.isFile() || contentOpened.size !== input.content_bytes || contentOpened.size > MAX_INPUT_BYTES) {
    closeSync(contentFd)
    return fail()
  }
  const content = readFileSync(contentFd)
  closeSync(contentFd)
  const hash = createHash('sha256').update(content).digest('hex')
  if (hash !== input.content_sha256) return fail()

  const client = new DefaultArtifactClient()
  const uploaded = await client.uploadArtifact(
    input.name,
    [contentPath],
    path.dirname(contentPath),
    {retentionDays: 7},
  )
  if (!Number.isSafeInteger(uploaded.id) || uploaded.id < 1 || !Number.isSafeInteger(uploaded.size)) return fail()
  const resultPath = process.env.PR_REVIEW_UPLOAD_RESULT
  if (!resultPath || !path.isAbsolute(resultPath)) return fail()
  writeFileSync(resultPath, JSON.stringify({status: 'UPLOADED', artifact_id: uploaded.id, size: uploaded.size}), {flag: 'wx', mode: 0o600})
}

main().catch(() => fail())
