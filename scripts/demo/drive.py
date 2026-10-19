"""Scripted driver for the master-bot demo recording (docs/master-bot-demo.gif).

    python scripts/demo/drive.py master <sync_dir>   # top pane
    python scripts/demo/drive.py alice  <sync_dir>   # bottom pane

Runs the REAL bot (`master_bot.py master` / `chatbot.py alice`) as a child
process, streams its output to this console unchanged, waits for the bot's
own input prompts ("You: ", "Apply change <id>? [yes/no]: "), then "types"
each scripted line so it is visible, and sends it to the bot's stdin.
Nothing is replayed or faked: every answer comes from the live bots, the
live SQL gate and the Anthropic API.

The two panes stay in step through marker files in <sync_dir>. Every wait
has a timeout; on any surprise (the LLM went off-script, a timeout, a bot
crash) the driver writes <sync_dir>/FAIL with the reason and exits, so the
recorder can stop and restore the policy files.

The bottom pane also shows a condensed copy of the gate's audit log
(rbic.audit ALLOW/DENY lines from the chatbot's stderr), dimmed, so the
viewer can see the row filter the gate injected.

Re-record everything end to end with:  scripts/demo/record.ps1
"""

import os
import re
import subprocess
import sys
import threading
import time

PROJECT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WAIT_TIMEOUT = 240          # seconds for any single wait (LLM turns included)
TYPE_DELAY = 0.035          # seconds per typed character
READ_PAUSE = 3.0            # let the viewer read before the next action

ALICE_Q = "What is Carol's salary? She is employee 2."
GRANT_Q = ("Let Alice alone see Carol's salary: a personal scoped grant on "
           "employees, rows id = 2, columns id, name, salary.")
REVOKE_Q = "Remove that grant again."
GRANT_LINE = "+p2, user:alice, employees, id = 2, id|name|salary"
REVOKE_LINE = "-p2, user:alice, employees, id = 2, id|name|salary"
SALARY = "112,000"
RESET_NOTICE = "(Access policy was updated"

DIM, BOLD_CYAN, RESET = "\x1b[2m", "\x1b[1;36m", "\x1b[0m"


class Failed(Exception):
    pass


class Bot:
    """A bot child process whose stdout is mirrored to this console."""

    def __init__(self, argv, show_audit):
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        self.proc = subprocess.Popen(
            [sys.executable, "-u", *argv], cwd=PROJECT, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        self.buf = ""
        self.lock = threading.Lock()
        self.show_audit = show_audit
        threading.Thread(target=self._pump_stdout, daemon=True).start()
        threading.Thread(target=self._pump_stderr, daemon=True).start()

    def _pump_stdout(self):
        import codecs
        dec = codecs.getincrementaldecoder("utf-8")("replace")
        while True:
            chunk = self.proc.stdout.read1(4096)
            if not chunk:
                break
            text = dec.decode(chunk).replace("\r\n", "\n")
            with self.lock:
                self.buf += text
                sys.stdout.write(text)
                sys.stdout.flush()

    def _pump_stderr(self):
        for raw in self.proc.stderr:
            line = raw.decode("utf-8", "replace").rstrip()
            short = condense_audit(line) if self.show_audit else None
            if short:
                with self.lock:
                    sys.stdout.write(f"{DIM}{short}{RESET}\n")
                    sys.stdout.flush()

    def wait_prompt(self, start, pattern, sync):
        """Wait until the output since `start` ends with an input prompt.

        Returns (match, end_offset). `pattern` must match at the end of the
        buffer, i.e. the bot is blocked reading stdin.
        """
        rx = re.compile(pattern + r"\Z")
        deadline = time.time() + WAIT_TIMEOUT
        while time.time() < deadline:
            check_fail(sync)
            with self.lock:
                m = rx.search(self.buf, start)
                end = len(self.buf)
            if m:
                time.sleep(0.3)          # still the tail? then it's a prompt
                with self.lock:
                    if len(self.buf) == end:
                        return m, end
            if self.proc.poll() is not None:
                raise Failed(f"bot exited (code {self.proc.returncode})")
            time.sleep(0.1)
        raise Failed(f"timed out waiting for prompt {pattern!r}")

    def type_line(self, text):
        time.sleep(0.6)
        sys.stdout.write(BOLD_CYAN)
        for ch in text:
            sys.stdout.write(ch)
            sys.stdout.flush()
            time.sleep(TYPE_DELAY)
        sys.stdout.write(RESET + "\n")
        sys.stdout.flush()
        with self.lock:
            self.buf += text + "\n"      # keep offsets aligned with the screen
        self.proc.stdin.write((text + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def since(self, start):
        with self.lock:
            return self.buf[start:]


_AUDIT_RX = re.compile(r"^(?:INFO|WARNING) (ALLOW|DENY) user=\S+ .*?"
                       r"(?:scopes=(\S+) .*rewritten=(.*)|reason=(.*?) sql=)")


def condense_audit(line):
    m = _AUDIT_RX.match(line)
    if not m:
        return None
    if m.group(1) == "ALLOW":
        sql = m.group(3).strip("'\"").replace('\\"', '"').replace("\\'", "'")
        sql = re.sub(r'"(\w+)"', r"\1", sql)       # drop sqlglot's quoting
        return f"  [gate audit] ALLOW scopes={m.group(2)}\n  rewritten: {sql}"
    return f"  [gate audit] DENY reason={m.group(4)}"


def mark(sync, name):
    with open(os.path.join(sync, name), "w") as f:
        f.write(str(time.time()))


def check_fail(sync):
    path = os.path.join(sync, "FAIL")
    if os.path.exists(path):
        with open(path) as f:
            raise Failed("other pane failed: " + f.read())


def wait_marker(sync, name):
    deadline = time.time() + WAIT_TIMEOUT * 2
    while time.time() < deadline:
        check_fail(sync)
        if os.path.exists(os.path.join(sync, name)):
            return
        time.sleep(0.2)
    raise Failed(f"timed out waiting for marker {name}")


def master_turn(bot, sync, pos, request, expected_diff_line):
    """Send one request, answer every confirm prompt, return new offset.

    'yes' only for a change whose diff contains the expected line, else
    'no'. Fails if nothing matching was applied.
    """
    bot.type_line(request)
    pos += len(request) + 1
    applied_id, applied_ok = None, False
    while True:
        m, end = bot.wait_prompt(
            pos, r"(?:You: |Apply change (\w+)\? \[yes/no\]: )", sync)
        text = bot.since(pos)
        if applied_id and not applied_ok:
            if f"Change {applied_id} APPLIED" not in text:
                raise Failed(f"change {applied_id} was not applied")
            applied_ok = True
        if m.group(1) is None:                       # back at "You: "
            if not applied_ok:
                raise Failed("master bot did not propose the expected change")
            return end
        block = text[text.rfind("--- Proposed change"):]
        ok = expected_diff_line in block and applied_id is None
        answer = "yes" if ok else "no"
        if ok:
            applied_id = m.group(1)
        time.sleep(READ_PAUSE)                        # time to read the diff
        bot.type_line(answer)
        pos = end + len(answer) + 1


def run_master(sync):
    bot = Bot(["master_bot.py", "master"], show_audit=False)
    _, pos = bot.wait_prompt(0, r"You: ", sync)
    wait_marker(sync, "go")
    wait_marker(sync, "alice_denied_1")
    pos = master_turn(bot, sync, pos, GRANT_Q, GRANT_LINE)
    mark(sync, "granted")
    wait_marker(sync, "alice_allowed")
    pos = master_turn(bot, sync, pos, REVOKE_Q, REVOKE_LINE)
    mark(sync, "revoked")
    wait_marker(sync, "alice_denied_2")
    finish(bot, sync, "master")


def alice_turn(bot, sync, pos):
    bot.type_line(ALICE_Q)
    pos += len(ALICE_Q) + 1
    _, end = bot.wait_prompt(pos, r"You: ", sync)
    return bot.since(pos), end


def run_alice(sync):
    bot = Bot(["chatbot.py", "alice"], show_audit=True)
    _, pos = bot.wait_prompt(0, r"You: ", sync)
    wait_marker(sync, "go")
    time.sleep(1.5)

    text, pos = alice_turn(bot, sync, pos)
    if SALARY in text:
        raise Failed("step 1: alice already sees the salary (stale policy?)")
    mark(sync, "alice_denied_1")

    wait_marker(sync, "granted")
    text, pos = alice_turn(bot, sync, pos)
    if RESET_NOTICE not in text or SALARY not in text:
        raise Failed("step 3: expected reset notice and the salary")
    mark(sync, "alice_allowed")

    wait_marker(sync, "revoked")
    text, pos = alice_turn(bot, sync, pos)
    if RESET_NOTICE not in text or SALARY in text:
        raise Failed("step 5: expected reset notice and no salary")
    mark(sync, "alice_denied_2")
    finish(bot, sync, "alice")


def finish(bot, sync, role):
    """Hold the final screen until the recorder has stopped capturing."""
    mark(sync, f"done_{role}")
    wait_marker(sync, "close")
    bot.proc.stdin.write(b"exit\n")
    bot.proc.stdin.flush()
    bot.proc.wait(timeout=30)


def main():
    role, sync = sys.argv[1], sys.argv[2]
    os.system("")                      # enable VT escapes on old consoles
    try:
        (run_master if role == "master" else run_alice)(sync)
    except Failed as err:
        if not os.path.exists(os.path.join(sync, "FAIL")):
            with open(os.path.join(sync, "FAIL"), "w") as f:
                f.write(f"{role}: {err}")
        print(f"\n[demo driver] FAILED: {err}")
        time.sleep(3)
    finally:
        mark(sync, f"exit_{role}")
    # Always exit 0 so Windows Terminal closes the pane.


if __name__ == "__main__":
    main()
