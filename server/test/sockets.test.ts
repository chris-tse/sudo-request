import { expect, test } from "bun:test"
import { statSync } from "node:fs"
import { parseConfig } from "../src/config"
import { Effect } from "effect"
import { mockExecutor, socketExecutor } from "../src/executor"
import { startApp } from "../src/main"
import { ORIGIN, tempDir, testConfigText } from "./helpers"

test("unix-socket deployment: permissions, CSP, and single instance", async () => {
  const dir = tempDir()
  const text = testConfigText(dir).replace('web_listen = "127.0.0.1:0"', `web_socket = "${dir}/web.sock"`)
  const config = parseConfig(text)
  const app = await startApp(config, mockExecutor())
  try {
    expect(statSync(`${dir}/web.sock`).mode & 0o777).toBe(0o600)
    expect(statSync(`${dir}/cli.sock`).mode & 0o777).toBe(0o666)

    const res = await fetch("http://localhost/api/requests", { unix: `${dir}/web.sock` } as any)
    expect(res.status).toBe(200)
    expect(res.headers.get("content-security-policy")).toContain("frame-ancestors 'none'")

    const deny = await fetch("http://localhost/api/requests/1/deny", {
      unix: `${dir}/web.sock`,
      method: "POST",
      headers: { Origin: ORIGIN, "Content-Type": "application/json", "Sec-Fetch-Site": "cross-site" },
      body: "{}",
    } as any)
    expect(deny.status).toBe(403)

    await expect(startApp(config, mockExecutor())).rejects.toThrow(/in use/)
  } finally {
    await app.stop()
  }
})

const writeSplit = async (s: { write(b: Uint8Array): number }, bytes: Buffer, at: number) => {
  s.write(bytes.subarray(0, at))
  await Bun.sleep(50)
  s.write(bytes.subarray(at))
}

test("CLI socket keeps a UTF-8 character intact when it is split across reads", async () => {
  const dir = tempDir()
  const app = await startApp(parseConfig(testConfigText(dir)), mockExecutor())
  try {
    const line = Buffer.from(JSON.stringify({ op: "submit", argv: ["echo", "é"], cwd: "/", user: "ctse", uid: 1000 }) + "\n")
    const splitAt = line.indexOf(Buffer.from("é")) + 1
    const reply = await new Promise<any>((resolve, reject) => {
      let buf = ""
      Bun.connect({
        unix: `${dir}/cli.sock`,
        socket: {
          open: (s) => void writeSplit(s, line, splitAt),
          data: (_s, d) => void (buf += d.toString()),
          close: () => resolve(JSON.parse(buf)),
          error: (_s, e) => reject(e),
        },
      }).catch(reject)
    })
    expect(reply.request.argv).toEqual(["echo", "é"])
  } finally {
    await app.stop()
  }
})

test("executor client keeps a UTF-8 character intact when it is split across reads", async () => {
  const path = `${tempDir()}/fake-executor.sock`
  const event = Buffer.from(JSON.stringify({ event: "finished", result: { stdout: "café\n" } }) + "\n")
  const server = Bun.listen({
    unix: path,
    socket: { data: (s) => void writeSplit(s, event, event.indexOf(Buffer.from("é")) + 1).then(() => s.end()) },
  })
  try {
    const outcome = await Effect.runPromise(socketExecutor(path).execute("{}", { credentialId: "a", clientDataJson: "b", authenticatorData: "c", signature: "d" }, () => {}))
    expect(outcome).toMatchObject({ _tag: "Finished", result: { stdout: "café\n" } })
  } finally {
    server.stop(true)
  }
})
