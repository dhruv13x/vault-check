# src/vault_check/dashboard.py
import asyncio
import time
from collections import deque
from typing import Dict, List, Callable, Optional

from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.text import Text
from rich.console import Console

# NOTE: these two modules must expose subscribe/publish hooks as shown later
from vault_check import registry, logging as vc_logging

console = Console()
REFRESH_DEFAULT = 8  # FPS


def build_status_table(statuses: Dict[str, dict]) -> Table:
    t = Table(expand=True, show_header=False, pad_edge=True)
    t.add_column("Verifier", ratio=2)
    t.add_column("Status", ratio=1, justify="right")
    # keep stable order: sort by category or insertion order
    for name, meta in statuses.items():
        st = meta.get("state", "pending")
        dur = meta.get("duration")
        extra = meta.get("message") or ""
        if st == "pending":
            label = "[yellow]⟳ running[/]"
        elif st == "ok":
            label = f"[green]✔ ok[/] {f'({dur:.0f}ms)' if dur else ''}"
        elif st == "fail":
            label = f"[red]✖ fail[/] {f'({dur:.0f}ms)' if dur else ''}"
        elif st == "warn":
            label = f"[yellow]⚠ warn[/]"
        else:
            label = f"[white]{st}[/]"
        # shorten long names/messages
        name_str = name if len(name) <= 36 else name[:33] + "..."
        if extra:
            label = label + " " + f"[dim]{extra if len(extra) < 40 else extra[:37] + '...'}[/]"
        t.add_row(name_str, label)
    return t


def build_logs_panel(log_lines: deque, max_lines: int = 12) -> Panel:
    # render last max_lines, already stored in deque
    text = "\n".join(list(log_lines)[-max_lines:])
    return Panel(Text(text, overflow="fold"), title="Logs", border_style="cyan")


class Dashboard:
    """
    Live dashboard for vault-check.

    Usage:
        dash = Dashboard()
        result = await dash.run(main_coroutine(), total_expected=num_verifiers, screen=True)
    """

    def __init__(self, refresher: int = REFRESH_DEFAULT, log_max: int = 500):
        self._statuses: Dict[str, dict] = {}
        self._logs: deque = deque(maxlen=log_max)
        self._refresh = refresher
        # set up subscriptions (no-op if registry/logging do not support)
        try:
            registry.subscribe_status(self._on_status)
        except Exception:
            # registry might not be instrumented yet; that's fine
            pass
        try:
            vc_logging.subscribe_console(self._on_log)
        except Exception:
            pass

    def _on_status(self, name: str, payload: dict):
        # Expected payload: {"state": "pending|ok|fail|warn", "duration": float_ms, "message": str}
        self._statuses[name] = payload

    def _on_log(self, text: str):
        # text is already formatted
        self._logs.append(text)

    async def run(
        self,
        coro,
        total_expected: Optional[int] = None,
        screen: bool = True,
        refresh: Optional[int] = None,
    ):
        """
        Run coroutine `coro` while presenting the dashboard.
        Returns a dict: {"ok": bool, "statuses": {...}, "logs": [...]}
        """
        refresh = refresh or self._refresh
        layout = Layout(name="root")
        # top area: two columns left: verifiers, right: logs
        layout.split(
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(Layout(name="left"), Layout(name="right", ratio=2))
        layout["left"].size = 48

        start = time.time()
        task = asyncio.create_task(coro)

        def footer_render():
            completed = sum(1 for v in self._statuses.values() if v.get("state") in ("ok", "fail", "warn"))
            total = total_expected or max(len(self._statuses), 1)
            elapsed = time.time() - start
            pct = (completed / total) * 100 if total else 0
            return Panel(f"Progress: {completed}/{total} ({pct:.0f}%)  Elapsed: {elapsed:.1f}s", border_style="magenta")

        # Live context: only create once
        with Live(layout, refresh_per_second=refresh, screen=screen):
            try:
                while not task.done():
                    # update panels (fast no-alloc)
                    layout["left"].update(Panel(build_status_table(self._statuses), title="Verifiers", border_style="green"))
                    layout["right"].update(build_logs_panel(self._logs))
                    layout["footer"].update(footer_render())
                    # nice small sleep to yield control
                    await asyncio.sleep(1 / refresh)
                # final update after task finished
                layout["left"].update(Panel(build_status_table(self._statuses), title="Verifiers", border_style="green"))
                layout["right"].update(build_logs_panel(self._logs))
                layout["footer"].update(footer_render())
                result = await task
            except asyncio.CancelledError:
                # caller cancelled (signal handling); show message and rethrow
                layout["right"].update(Panel(Text("Shutdown requested..."), title="Logs"))
                raise
            except Exception as exc:
                # show a summary of exception
                summary = Panel(Text(str(exc)), title="Exception", border_style="red")
                layout["left"].update(Panel(build_status_table(self._statuses), title="Verifiers"))
                layout["right"].update(summary)
                # give user a moment to read before re-raising
                await asyncio.sleep(0.5)
                raise

        # after exiting Live: build final structured summary
        status_values = [v.get("state") for v in self._statuses.values()]
        final_ok = all(s == "ok" for s in status_values) and len(status_values) > 0
        return {"ok": final_ok, "statuses": dict(self._statuses), "logs": list(self._logs)}