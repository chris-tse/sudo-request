import type { ReactNode } from "react"

// Characters that could make the displayed command differ from what runs:
// control characters, bidi overrides, zero-width characters.
const SPECIAL = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g

const NAMED: Record<string, string> = { "\n": "\\n", "\t": "\\t", "\r": "\\r" }

const escapeChar = (c: string) => NAMED[c] ?? `\\u{${c.codePointAt(0)!.toString(16).padStart(4, "0")}}`

/** Renders text with any special characters as visible, highlighted escapes. */
export const Visible = ({ text }: { text: string }) => {
  const parts: ReactNode[] = []
  let last = 0
  for (const m of text.matchAll(SPECIAL)) {
    if (m.index > last) parts.push(text.slice(last, m.index))
    parts.push(
      <mark key={m.index} className="esc">
        {escapeChar(m[0])}
      </mark>,
    )
    last = m.index + m[0].length
  }
  parts.push(text.slice(last))
  return <>{parts}</>
}

const SAFE = /^[A-Za-z0-9_\-./=:,+@%]+$/

export const shellQuote = (arg: string) => (SAFE.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`)

export const Command = ({ argv }: { argv: string[] }) => (
  <code className="command">
    {argv.map((a, i) => (
      <span key={i} className="arg">
        <Visible text={shellQuote(a)} />
      </span>
    ))}
  </code>
)

export const time = (ms: number) =>
  new Date(ms).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })

export const relative = (ms: number, now: number) => {
  const s = Math.round((ms - now) / 1000)
  const abs = Math.abs(s)
  const text = abs < 60 ? `${abs}s` : abs < 3600 ? `${Math.floor(abs / 60)}m ${abs % 60}s` : `${Math.floor(abs / 3600)}h`
  return s >= 0 ? `in ${text}` : `${text} ago`
}
