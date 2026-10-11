import {spawn} from 'node:child_process'
import path from 'node:path'
import process from 'node:process'

const MAX_RUNTIME_MS = 240_000
const CLEANUP_GRACE_MS = 250
const MAX_OUTCOME_BYTES = 8 * 1024
const OUTCOME_SCHEMA = 'pr-review-protected-publication.v1'
const OUTCOME_STATUSES = new Set(['CONFIRMED', 'REJECTED', 'UNKNOWN', 'DEFERRED', 'STALE', 'CONFLICT', 'CANDIDATE', 'DISABLED'])
const REASON = /^[a-z0-9_]{1,64}$/
const ACTOR = /^[A-Za-z0-9-]{1,39}(?:\[bot\])?$/

const ALLOWED_ENV = [
  'PATH',
  'HOME',
  'TMPDIR',
  'RUNNER_TEMP',
  'RUNNER_TRACKING_ID',
  'GITHUB_WORKSPACE',
  'GITHUB_REPOSITORY',
  'GITHUB_REPOSITORY_ID',
  'GITHUB_RUN_ID',
  'GITHUB_RUN_ATTEMPT',
  'GITHUB_REF',
  'GITHUB_SHA',
  'GITHUB_EVENT_PATH',
  'GITHUB_EVENT_NAME',
  'GITHUB_WORKFLOW',
  'GITHUB_WORKFLOW_REF',
  'GITHUB_WORKFLOW_SHA',
  'GITHUB_TOKEN',
  'ACTIONS_RUNTIME_TOKEN',
  'ACTIONS_RESULTS_URL',
  'ACTIONS_RUNTIME_URL',
  'PR_REVIEW_PUBLISHER_WORKFLOW_ID',
  'PR_REVIEW_PUBLISHER_WORKFLOW_PATH',
  'PR_REVIEW_ANALYSIS_WORKFLOW_ID',
  'PR_REVIEW_ANALYSIS_WORKFLOW_NAME',
  'PR_REVIEW_ANALYSIS_WORKFLOW_PATH',
  'PR_REVIEW_ANALYSIS_WORKFLOW_REF',
  'PR_REVIEW_PUBLISHER_ACTOR',
  'PYTHONPATH',
]

function terminate(child, signal) {
  try {
    if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signal)
    else child.kill(signal)
  } catch {}
}

function waitForExit(exit, milliseconds) {
  let timer
  return Promise.race([
    exit.then(() => true, () => true),
    new Promise((resolve) => {
      timer = setTimeout(() => resolve(false), milliseconds)
    }),
  ]).finally(() => clearTimeout(timer))
}

async function stopChild(child, exit) {
  terminate(child, 'SIGTERM')
  if (await waitForExit(exit, CLEANUP_GRACE_MS)) return
  terminate(child, 'SIGKILL')
  await waitForExit(exit, CLEANUP_GRACE_MS)
}

function safeFailure() {
  process.stderr.write('protected_publication_launcher_failed\n')
  return 1
}

function validateOutcome(raw, env) {
  if (raw.length === 0 || raw.length > MAX_OUTCOME_BYTES) return null
  for (const key of ['ACTIONS_RUNTIME_TOKEN', 'GITHUB_TOKEN']) {
    const secret = env[key]
    if (typeof secret === 'string' && secret.length > 0 && raw.includes(Buffer.from(secret))) return null
  }
  let value
  try {
    value = JSON.parse(raw.toString('utf8'))
  } catch {
    return null
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const allowed = new Set(['schema', 'status', 'reason', 'no_effect_receipt', 'effect_observation'])
  if (Object.keys(value).some((key) => !allowed.has(key))) return null
  if (value.schema !== OUTCOME_SCHEMA || !OUTCOME_STATUSES.has(value.status)) return null
  if (value.reason !== null && (typeof value.reason !== 'string' || !REASON.test(value.reason))) return null

  const safe = {schema: OUTCOME_SCHEMA, status: value.status, reason: value.reason}
  if (Object.hasOwn(value, 'no_effect_receipt')) {
    const receipt = value.no_effect_receipt
    if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) return null
    if (
      Object.keys(receipt).length !== 2 || !Object.hasOwn(receipt, 'status') || !Object.hasOwn(receipt, 'reason') ||
      !['ACKNOWLEDGED', 'UNKNOWN'].includes(receipt.status)
    ) return null
    if (typeof receipt.reason !== 'string' || !REASON.test(receipt.reason)) return null
    safe.no_effect_receipt = {status: receipt.status, reason: receipt.reason}
  }
  if (Object.hasOwn(value, 'effect_observation')) {
    const observation = value.effect_observation
    if (!observation || typeof observation !== 'object' || Array.isArray(observation)) return null
    if (
      Object.keys(observation).length !== 4 ||
      ['actor_login', 'review_state', 'review_id', 'write_capability'].some((key) => !Object.hasOwn(observation, key))
    ) return null
    if (
      typeof observation.actor_login !== 'string' || !ACTOR.test(observation.actor_login) ||
      !['APPROVED', 'CHANGES_REQUESTED', 'COMMENTED'].includes(observation.review_state) ||
      !Number.isSafeInteger(observation.review_id) || observation.review_id <= 0 ||
      observation.write_capability !== 'OBSERVED_SUCCESS' || value.status !== 'CONFIRMED'
    ) return null
    safe.effect_observation = {
      actor_login: observation.actor_login,
      review_state: observation.review_state,
      review_id: observation.review_id,
      write_capability: 'OBSERVED_SUCCESS',
    }
  }
  return safe
}

export async function runProtectedPublication({
  deadlineMs = MAX_RUNTIME_MS,
  spawnProcess = spawn,
  env = process.env,
} = {}) {
  if (!Number.isInteger(deadlineMs) || deadlineMs <= 0 || deadlineMs > MAX_RUNTIME_MS) return safeFailure()
  if (
    typeof env.GITHUB_WORKSPACE !== 'string' || !path.isAbsolute(env.GITHUB_WORKSPACE) ||
    typeof env.PYTHONPATH !== 'string' || !path.isAbsolute(env.PYTHONPATH) ||
    typeof env.ACTIONS_RUNTIME_TOKEN !== 'string' || !env.ACTIONS_RUNTIME_TOKEN ||
    typeof env.ACTIONS_RESULTS_URL !== 'string' || !env.ACTIONS_RESULTS_URL
  ) return safeFailure()

  const childEnv = {}
  for (const key of ALLOWED_ENV) {
    if (typeof env[key] === 'string') childEnv[key] = env[key]
  }

  let child
  let timer
  let timedOut = false
  let resolveDeadline
  const deadline = new Promise((resolve) => { resolveDeadline = resolve })
  let outputOverflow = false
  const output = []
  let outputBytes = 0
  let resolveExit
  const exit = new Promise((resolve) => { resolveExit = resolve })
  let resolveCancelled
  let cancelledBy
  const cancelled = new Promise((resolve) => { resolveCancelled = resolve })
  const onSignal = (signal) => {
    cancelledBy = signal
    timedOut = true
    void stopChild(child, exit).finally(() => resolveCancelled({cancelledBy: signal}))
  }
  const onSigterm = () => onSignal('SIGTERM')
  const onSigint = () => onSignal('SIGINT')
  try {
    child = spawnProcess('python', ['-P', '-m', 'pr_review_harness.protected_publication_runtime'], {
      cwd: childEnv.GITHUB_WORKSPACE,
      env: childEnv,
      stdio: ['ignore', 'pipe', 'ignore'],
      detached: process.platform !== 'win32',
    })
    child.stdout.on('data', (chunk) => {
      if (outputOverflow) return
      outputBytes += chunk.length
      if (outputBytes > MAX_OUTCOME_BYTES) {
        outputOverflow = true
        void stopChild(child, exit)
        return
      }
      output.push(Buffer.from(chunk))
    })
    child.once('error', () => resolveExit({error: true}))
    child.once('close', (code, signal) => resolveExit({code, signal}))
  } catch {
    return safeFailure()
  }
  process.once('SIGTERM', onSigterm)
  process.once('SIGINT', onSigint)

  timer = setTimeout(() => {
    timedOut = true
    void stopChild(child, exit).finally(() => resolveDeadline({timeout: true}))
  }, deadlineMs)
  const result = await Promise.race([exit, deadline, cancelled])
  clearTimeout(timer)
  process.removeListener('SIGTERM', onSigterm)
  process.removeListener('SIGINT', onSigint)
  if (cancelledBy) {
    process.exitCode = cancelledBy === 'SIGTERM' ? 143 : 130
    return process.exitCode
  }
  if (timedOut || result.error || outputOverflow) return safeFailure()
  if (Number.isInteger(result.code) && result.code >= 0 && result.code <= 255) {
    if (result.code !== 0) return result.code
    const safe = validateOutcome(Buffer.concat(output), env)
    if (!safe) return safeFailure()
    process.stdout.write(`${JSON.stringify(safe)}\n`)
    return 0
  }
  return safeFailure()
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = await runProtectedPublication()
}
