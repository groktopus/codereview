import {spawn} from 'node:child_process'
import process from 'node:process'
import {pathToFileURL} from 'node:url'
import {runHostedRecovery} from './hosted-recovery.mjs'

const MAX_OUTPUT_BYTES = 64 * 1024
const DEADLINE_MS = 150_000
const CLEANUP_GRACE_MS = 250
const FINAL_CLOSE_GRACE_MS = 50

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

function signalOwnedProcessGroup(child, signal) {
  try {
    if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signal)
    else child.kill(signal)
  } catch {}
}

function waitForClose(exit, waitMs) {
  let timer
  return Promise.race([
    exit.then(() => true, () => true),
    new Promise((resolve) => {
      timer = setTimeout(() => resolve(false), waitMs)
    }),
  ]).finally(() => clearTimeout(timer))
}

async function stopOwnedChild(child, exit) {
  signalOwnedProcessGroup(child, 'SIGTERM')
  if (await waitForClose(exit, CLEANUP_GRACE_MS)) return

  signalOwnedProcessGroup(child, 'SIGKILL')
  if (await waitForClose(exit, CLEANUP_GRACE_MS)) return

  // An escaped descendant can keep the inherited stdout pipe open after the
  // owned process group has been killed. Close only our pipe; do not signal an
  // unrelated descendant that deliberately left the owned process group.
  child.stdout?.destroy()
  await waitForClose(exit, FINAL_CLOSE_GRACE_MS)
}

function unknown(reason, exitCode = 1) {
  return {
    stdout: `{"state":"UNKNOWN","reason":"${reason}","safe_to_publish":false}\n`,
    exitCode,
  }
}

export async function runCanary({deadlineMs = DEADLINE_MS, spawnProcess = spawn, env = process.env} = {}) {
  if (!Number.isInteger(deadlineMs) || deadlineMs <= 0 || deadlineMs > DEADLINE_MS) {
    return unknown('canary_runtime_failed')
  }
  if (!env.ACTIONS_RUNTIME_TOKEN || !env.ACTIONS_RESULTS_URL || !env.GITHUB_WORKSPACE) {
    return unknown('actions_runtime_unavailable', 0)
  }
  const childEnv = {}
  for (const key of allowed) {
    if (typeof env[key] === 'string') childEnv[key] = env[key]
  }
  childEnv.PYTHONPATH = childEnv.PYTHONPATH || 'src'

  let child
  try {
    child = spawnProcess('python', ['-m', 'pr_review_harness.actions_runtime'], {
      cwd: childEnv.GITHUB_WORKSPACE,
      env: childEnv,
      stdio: ['ignore', 'pipe', 'ignore'],
      detached: process.platform !== 'win32',
    })
  } catch {
    return unknown('canary_runtime_failed')
  }

  const chunks = []
  let outputBytes = 0
  let exceeded = false
  const closed = new Promise((resolve) => {
    child.once('close', (code, signal) => resolve({code, signal}))
  })
  // Spawn errors and child close are distinct: an error does not prove that a
  // process with a PID has exited or that its owned process group is closed.
  const exit = new Promise((resolve, reject) => {
    child.once('error', reject)
    closed.then(resolve)
  })
  exit.catch(() => {})
  const outputLimit = new Promise((resolve) => {
    child.stdout?.on('data', (chunk) => {
      outputBytes += chunk.length
      if (outputBytes > MAX_OUTPUT_BYTES) {
        exceeded = true
        child.stdout.pause()
        resolve('oversized')
        return
      }
      chunks.push(chunk)
    })
  })
  const deadline = Date.now() + deadlineMs
  let timeout
  const timedOut = new Promise((resolve) => {
    timeout = setTimeout(() => resolve('deadline'), Math.max(1, deadline - Date.now()))
  })

  let outcome
  try {
    outcome = await Promise.race([exit, timedOut, outputLimit])
  } catch {
    if (child.pid) await stopOwnedChild(child, closed)
    return unknown('canary_runtime_failed')
  } finally {
    clearTimeout(timeout)
  }

  if (outcome === 'deadline' || outcome === 'oversized') {
    await stopOwnedChild(child, closed)
    return unknown(outcome === 'deadline' ? 'canary_deadline_exhausted' : 'canary_runtime_failed_or_oversized')
  }
  if (exceeded || outcome.code !== 0 || outcome.signal) {
    return unknown('canary_runtime_failed_or_oversized')
  }
  const output = Buffer.concat(chunks)
  if (!output.length || output[output.length - 1] !== 10) {
    return unknown('canary_output_invalid')
  }
  return {stdout: output, exitCode: 0}
}

async function main() {
  if (process.env.INPUT_MODE === 'hosted-recovery-run-a') {
    await runHostedRecovery()
    return
  }
  const result = await runCanary()
  process.stdout.write(result.stdout)
  if (result.exitCode !== 0) process.exitCode = result.exitCode
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    if (process.env.INPUT_MODE === 'hosted-recovery-run-a') {
      process.stderr.write('{"status":"failed","error_code":"hosted_recovery_action_failed"}\n')
    } else {
      process.stdout.write('{"state":"UNKNOWN","reason":"canary_runtime_failed","safe_to_publish":false}\n')
    }
    process.exitCode = 1
  })
}
