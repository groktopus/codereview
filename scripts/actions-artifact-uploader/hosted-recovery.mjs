import {spawn} from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

const MAX_OUTPUT_BYTES = 64 * 1024
const MAX_ERROR_BYTES = 4 * 1024
const MAX_RUNTIME_MS = 500_000
const CLEANUP_GRACE_MS = 400
const FINAL_CLOSE_GRACE_MS = 100

const forwardedEnvironment = [
  'PATH', 'HOME', 'TMPDIR', 'GITHUB_WORKSPACE', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID',
  'GITHUB_RUN_ATTEMPT', 'GITHUB_REF', 'GITHUB_SHA', 'GITHUB_WORKFLOW_REF',
  'ACTIONS_RUNTIME_TOKEN', 'ACTIONS_RESULTS_URL', 'ACTIONS_RUNTIME_URL',
]

function safeInputs(env) {
  const root = env.INPUT_ROOT
  const stage = env.INPUT_STAGE
  const sourceRoot = env.INPUT_SOURCE_ROOT
  const wheel = env.INPUT_WHEEL
  const workspace = env.GITHUB_WORKSPACE
  if (![root, stage, sourceRoot, wheel, workspace].every((value) => typeof value === 'string' && path.isAbsolute(value))) {
    throw new Error('hosted_recovery_action_inputs_invalid')
  }
  if (path.resolve(sourceRoot) !== path.resolve(workspace)) throw new Error('hosted_recovery_action_source_root_invalid')
  const runnerTemp = env.RUNNER_TEMP
  if (!runnerTemp || !path.isAbsolute(runnerTemp)) throw new Error('hosted_recovery_action_runner_temp_invalid')
  for (const candidate of [root, stage, wheel]) {
    const rel = path.relative(path.resolve(runnerTemp), path.resolve(candidate))
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) throw new Error('hosted_recovery_action_path_invalid')
  }
  const stat = fs.lstatSync(wheel)
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 6_000_000) {
    throw new Error('hosted_recovery_action_wheel_invalid')
  }
  if (!env.ACTIONS_RUNTIME_TOKEN || !env.ACTIONS_RESULTS_URL || !env.GITHUB_RUN_ID || !env.GITHUB_RUN_ATTEMPT) {
    throw new Error('hosted_recovery_action_runtime_unavailable')
  }
  return {root, stage, sourceRoot, wheel, workspace}
}

function signalGroup(child, signal) {
  try {
    if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signal)
    else child.kill(signal)
  } catch {}
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function stopChild(child, closed) {
  signalGroup(child, 'SIGTERM')
  if (await Promise.race([closed.then(() => true), delay(CLEANUP_GRACE_MS).then(() => false)])) return
  signalGroup(child, 'SIGKILL')
  if (await Promise.race([closed.then(() => true), delay(CLEANUP_GRACE_MS).then(() => false)])) return
  child.stdout?.destroy()
  child.stderr?.destroy()
  await Promise.race([closed.then(() => true), delay(FINAL_CLOSE_GRACE_MS)])
}

export async function runHostedRecovery({env = process.env, spawnProcess = spawn, deadlineMs = MAX_RUNTIME_MS} = {}) {
  if (!Number.isInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > MAX_RUNTIME_MS) {
    throw new Error('hosted_recovery_action_deadline_invalid')
  }
  const inputs = safeInputs(env)
  const script = path.join(inputs.workspace, 'scripts', 'hosted_recovery_rehearsal.py')
  const childEnv = {}
  for (const name of forwardedEnvironment) {
    if (typeof env[name] === 'string') childEnv[name] = env[name]
  }
  childEnv.PATH ||= ''
  childEnv.HOME ||= env.RUNNER_TEMP
  childEnv.TMPDIR ||= env.RUNNER_TEMP
  const args = [script, 'run-a', '--root', inputs.root, '--stage', inputs.stage,
    '--source-root', inputs.sourceRoot, '--wheel', inputs.wheel]
  let child
  try {
    child = spawnProcess('python', args, {
      cwd: inputs.workspace,
      env: childEnv,
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: process.platform !== 'win32',
    })
  } catch {
    throw new Error('hosted_recovery_helper_spawn_failed')
  }

  let outputBytes = 0
  let errorBytes = 0
  let exceeded = false
  const closed = new Promise((resolve, reject) => {
    child.once('error', reject)
    child.once('close', (code, signal) => resolve({code, signal}))
  })
  closed.catch(() => {})
  child.stdout?.on('data', (chunk) => {
    outputBytes += chunk.length
    if (outputBytes > MAX_OUTPUT_BYTES) {
      exceeded = true
      child.stdout.pause()
      signalGroup(child, 'SIGTERM')
      return
    }
    process.stdout.write(chunk)
  })
  child.stderr?.on('data', (chunk) => {
    errorBytes += chunk.length
    if (errorBytes > MAX_ERROR_BYTES) {
      exceeded = true
      child.stderr.pause()
      signalGroup(child, 'SIGTERM')
      return
    }
    process.stderr.write(chunk)
  })

  // GitHub sends SIGINT to the action entry point during cancellation. Forward
  // it to the helper so its finally block closes the held fake provider/CLI.
  const forwardInterrupt = () => signalGroup(child, 'SIGINT')
  const forwardTerminate = () => signalGroup(child, 'SIGTERM')
  process.on('SIGINT', forwardInterrupt)
  process.on('SIGTERM', forwardTerminate)
  let timer
  try {
    const timedOut = new Promise((resolve) => {
      timer = setTimeout(() => resolve('deadline'), deadlineMs)
    })
    const oversized = new Promise((resolve) => {
      const poll = setInterval(() => {
        if (exceeded) {
          clearInterval(poll)
          resolve('oversized')
        }
      }, 10)
      poll.unref?.()
    })
    const outcome = await Promise.race([closed, timedOut, oversized])
    if (outcome === 'deadline' || outcome === 'oversized') {
      await stopChild(child, closed)
      throw new Error(outcome === 'deadline' ? 'hosted_recovery_action_deadline_exhausted' : 'hosted_recovery_action_output_exceeded')
    }
    if (exceeded) throw new Error('hosted_recovery_action_output_exceeded')
    if (outcome.signal || outcome.code !== 0 || exceeded) {
      throw new Error('hosted_recovery_helper_failed')
    }
  } finally {
    clearTimeout(timer)
    process.off('SIGINT', forwardInterrupt)
    process.off('SIGTERM', forwardTerminate)
  }
}
