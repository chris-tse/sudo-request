## Privileged commands (sudo-request)

When a command needs root, tell the user which command needs to run and why.
Do not submit it on your own initiative. Many diagnostics work without root,
so try that first.

If the user explicitly tells you to use `sudo-request`:

1. Submit without `sudo`, as an argument list:
   `sudo-request submit -- ufw allow 22/tcp`
2. Tell the user the request ID and that it is waiting for approval on the dashboard.
3. Run `sudo-request wait <id>` (add `--timeout 600` if your tool calls time out).
   It prints the command's stdout and stderr and exits with its exit code.
   Exit code 3 means denied, cancelled, or expired. Exit code 4 means it failed to
   start or its outcome is uncertain.
4. Never resubmit a request whose outcome is `uncertain` without asking. It may
   already have run.

Do not try to approve requests yourself, open the approval dashboard, or
reach the executor. Approval is the human's step.
