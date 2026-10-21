import { realpathSync, statSync } from "node:fs"
import { basename, dirname, isAbsolute, join, resolve } from "node:path"

/** Same as the executor's PATH; user PATH entries (e.g. ~/.local/bin) are never consulted. */
export const SECURE_PATH = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]

type Trust = { ok: true } | { ok: false; reason: string }

/** Every component of the resolved path is root-owned and not group/world-writable. */
export const rootControlled = (path: string): Trust => {
  let real: string
  try {
    real = realpathSync(path)
  } catch (e: any) {
    return { ok: false, reason: e.code === "EACCES" ? "cannot be inspected" : "does not exist" }
  }
  for (let p = real; ; p = dirname(p)) {
    let st
    try {
      st = statSync(p)
    } catch {
      return { ok: false, reason: "cannot be inspected" }
    }
    if (st.uid !== 0) return { ok: false, reason: `${p} is not owned by root` }
    if (st.mode & 0o022) return { ok: false, reason: `${p} is group/world-writable` }
    if (p === "/") return { ok: true }
  }
}

const isExecutableFile = (p: string) => {
  try {
    const st = statSync(p)
    return st.isFile() && (st.mode & 0o111) !== 0
  } catch {
    return false
  }
}

export const resolveExecutable = (argv0: string, cwd: string): { ok: true; path: string } | { ok: false; message: string } => {
  if (argv0.includes("/")) {
    const path = isAbsolute(argv0) ? argv0 : resolve(cwd, argv0)
    const trust = rootControlled(path)
    if (!trust.ok) {
      return {
        ok: false,
        message: `${path} ${trust.reason}; only root-controlled executables can be run (a non-root user could change this file after approval)`,
      }
    }
    return isExecutableFile(path) ? { ok: true, path } : { ok: false, message: `${path} is not an executable file` }
  }
  for (const dir of SECURE_PATH) {
    const candidate = join(dir, argv0)
    if (isExecutableFile(candidate) && rootControlled(candidate).ok) return { ok: true, path: candidate }
  }
  return { ok: false, message: `${argv0}: not found in ${SECURE_PATH.join(":")} (pass an absolute path if it lives elsewhere)` }
}

const CODE_RUNNERS = new Set([
  "sh", "bash", "dash", "zsh", "fish", "ksh", "busybox",
  "python", "python3", "perl", "ruby", "node", "bun", "deno", "php", "lua", "tclsh",
  "env", "sudo", "su", "doas", "pkexec", "xargs", "nohup", "setsid", "timeout", "nice", "ionice",
  "watch", "systemd-run", "chroot", "unshare", "nsenter", "flock", "script",
])

const INVISIBLE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/

/**
 * Advisory notes for the human. These are not a security control: they point
 * out the cases where approving the visible command does not pin down what
 * actually runs.
 */
export const warningsFor = (executable: string, argv: string[], cwd: string): string[] => {
  const warnings: string[] = []
  const name = basename(executable).replace(/\d+(\.\d+)*$/, "")
  if (CODE_RUNNERS.has(name) || CODE_RUNNERS.has(basename(executable))) {
    warnings.push(`${basename(executable)} can run arbitrary code: review exactly what it will execute.`)
  }
  if (argv.some((a) => INVISIBLE.test(a))) {
    warnings.push("The command contains control or invisible Unicode characters (shown highlighted).")
  }
  argv.slice(1).forEach((arg, i) => {
    const looksLikePath = arg.startsWith("/") || arg.startsWith("./") || arg.startsWith("../") || arg.startsWith("~")
    if (!looksLikePath || arg.startsWith("~")) {
      if (arg.startsWith("~")) warnings.push(`Argument ${i + 1} (${arg}) uses ~, which is not expanded: it is passed literally.`)
      return
    }
    const path = resolve(cwd, arg)
    const trust = rootControlled(path)
    if (trust.ok || trust.reason === "does not exist") return
    warnings.push(
      trust.reason === "cannot be inspected"
        ? `Argument ${i + 1} (${arg}) is in a location the dashboard cannot inspect (likely a home directory); its contents may change before it runs.`
        : `Argument ${i + 1} (${arg}) is writable by a non-root user (${trust.reason}); its contents may change before it runs.`,
    )
  })
  return warnings
}
