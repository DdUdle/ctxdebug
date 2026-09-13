# IDA -S helper: wait for analysis, start the HTTP bridge, keep idat alive.
import pathlib
import sys
import time

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))

try:
    import ida_auto
    ida_auto.auto_wait()
except Exception:
    pass

mod = sys.modules.get("ida_server_plugin")
if mod is None:
    import ida_server_plugin as mod

mod.start()
if getattr(mod, "_server_instance", None) is None:
    raise RuntimeError("ida_server_plugin failed to bind HTTP port 2022")

ready = pathlib.Path(__file__).with_name("_ida_http_ready")
ready.write_text("ok", encoding="utf-8")
# Must pump on IDA's main thread — time.sleep would starve execute_sync
# and IDA 9 refuses inf_* / idautils from the HTTP worker thread.
mod.pump_forever()
