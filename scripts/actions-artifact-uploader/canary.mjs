import {spawn} from 'node:child_process'
import process from 'node:process'

const MAX_OUTPUT_BYTES = 64 * 1024
const DEADLINE_MS = 150_000

const allowed = [
  'PATH',
  'HOME',
  'TMPDIR',
  'GITHUB_WORKSPACE',
  'GITHUB_REPOSITORY',
  'GITHUB_RUN_ID',
  'GITHUB_RUN_ATTEMPT',
  'GITHUB_REF',
  'GITHUB_SHA',
  'GITHUB_EVENT_PATH',
  'GITHUB_TOKEN',
  'ACTIONS_RUNTIME_TOKEN',
  'ACTIONS_RESULTS_URL',
  'ACTIONS_RUNTIME_URL',
  'PR_REVIEW_PUBLISHER_WORKFLOW_ID',
  'PR_REVIEW_PUBLISHER_WORKFLOW_PATH',
  'PR_REVIEW_ANALYSIS_WORKFLOW_ID',
  'PR_REVIEW_ANALYSIS_WORKFLOW_PATH',
  'PR_REVIEW_ANALYSIS_WORKFLOW_REF',
  'PR_REVIEW_PUBLISHER_ACTOR',
  'PYTHONPATH',
]

function terminate(child) {
  try {
    if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGTERM')
    else child.kill('SIGTERM')
  } catch {}
  const timer = setTimeout(() => {
    try {
      if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGKILL')
      else child.kill('SIGKILL')
    } catch {}
  }, 250)
  timer.unref()
}

async function main() {
  if (!process.env.ACTIONS_RUNTIME_TOKEN || !process.env.ACTIONS_RESULTS_URL || !process.env.GITHUB_WORKSPACE) {
    process.stdout.write('{"state":"UNKNOWN","reason":"actions_runtime_unavailable","safe_to_publish":false}\n')
    return
  }
  const childEnv = {}
  for (const key of allowed) {
    if (typeof process.env[key] === 'string') childEnv[key] = process.env[key]
  }
  childEnv.PYTHONPATH = childEnv.PYTHONPATH || 'src'
  const child = spawn('python', ['-m', 'pr_review_harness.actions_runtime'], {
    cwd: childEnv.GITHUB_WORKSPACE,
    env: childEnv,
    stdio: ['ignore', 'pipe', 'ignore'],
    detached: process.platform !== 'win32',
  })
  const chunks = []
  let outputBytes = 0
  let exceeded = false
  child.stdout.on('data', (chunk) => {
    outputBytes += chunk.length
    if (outputBytes > MAX_OUTPUT_BYTES) {
      exceeded = true
      terminate(child)
      return
    }
    chunks.push(chunk)
  })
  const deadline = Date.now() + DEADLINE_MS
  const exit = new Promise((resolve, reject) => {
    child.once('error', reject)
    child.once('close', (code, signal) => resolve({code, signal}))
  })
  let timeout
  const timedOut = new Promise((resolve) => {
    timeout = setTimeout(() => resolve(null), Math.max(1, deadline - Date.now()))
  })
  const outcome = await Promise.race([exit, timedOut])
  clearTimeout(timeout)
  if (outcome === null) {
    terminate(child)
    await exit.catch(() => {})
    process.stdout.write('{"state":"UNKNOWN","reason":"canary_deadline_exhausted","safe_to_publish":false}\n')
    process.exitCode = 1
    return
  }
  if (exceeded || outcome.code !== 0 || outcome.signal) {
    process.stdout.write('{"state":"UNKNOWN","reason":"canary_runtime_failed_or_oversized","safe_to_publish":false}\n')
    process.exitCode = 1
    return
  }
  const output = Buffer.concat(chunks)
  if (!output.length || output[output.length - 1] !== 10) {
    process.stdout.write('{"state":"UNKNOWN","reason":"canary_output_invalid","safe_to_publish":false}\n')
    process.exitCode = 1
    return
  }
  process.stdout.write(output)
}

main().catch(() => {
  process.stdout.write('{"state":"UNKNOWN","reason":"canary_runtime_failed","safe_to_publish":false}\n')
  process.exitCode = 1
})
