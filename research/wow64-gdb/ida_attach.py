import argparse
import os
import struct
import subprocess
import time

import idapro
import ida_auto
import ida_dbg
import ida_ida
import ida_idd
import ida_netnode
import ida_segment
import ida_ua
import idc


def _try_reg(name):
    try:
        return idc.get_reg_value(name)
    except Exception as e:
        return "error: %s" % e


def describe(label):
    ea = ida_dbg.get_ip_val()
    if ea is None:
        print("%-30s get_ip_val() is None; eip=%r" % (label, _try_reg("eip")), flush=True)
        return
    try:
        cs = idc.get_reg_value("cs")
    except Exception:
        cs = None
    seg = ida_segment.getseg(ea)
    segname = ida_segment.get_segm_name(seg) if seg else None
    bits = seg.bitness if seg else None
    insn = idc.generate_disasm_line(ea, 0) if seg else None
    print("%-30s ip=0x%x cs=%s seg=%s bitness=%s insn=%r" % (label, ea, hex(cs) if cs is not None else None, segname, bits, insn), flush=True)


def modules():
    m = ida_idd.modinfo_t()
    out = []
    ok = ida_dbg.get_first_module(m)
    while ok:
        out.append((m.base, m.size, m.name))
        ok = ida_dbg.get_next_module(m)
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("database")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--analyzer-cmd", required=True)
    p.add_argument("--events", type=int, default=40)
    p.add_argument("--steps", type=int, default=0)
    p.add_argument("--bpt", type=lambda x: int(x, 0), action="append", default=[])
    p.add_argument("--set-64bit", action="store_true")
    p.add_argument("--stop-at", type=lambda x: int(x, 0))
    a = p.parse_args()

    idapro.open_database(os.path.abspath(a.database), True)
    ida_auto.auto_wait()
    print("database bitness:", 64 if ida_ida.inf_is_64bit() else 32, "entry", hex(ida_ida.inf_get_start_ea()), flush=True)

    if a.set_64bit:
        ida_ida.inf_set_64bit(True)
        print("database bitness now:", 64 if ida_ida.inf_is_64bit() else 32, flush=True)
    backend = subprocess.Popen(a.analyzer_cmd, shell=True, stdout=open("/tmp/wow64gdb/ida-analyzer.log", "w"), stderr=subprocess.STDOUT)
    time.sleep(2)
    try:
        node = ida_netnode.netnode()
        node.create("$ gdb options")
        node.supset(6, struct.pack("<q", 1), 8)
        node.supset(7, "")
        idc.batch(1)
        ida_dbg.load_debugger("", False)
        assert ida_dbg.load_debugger("gdb", True)
        ida_dbg.set_remote_debugger("127.0.0.1", "", a.port)
        ida_dbg.set_process_options(os.path.basename(a.database), "", "", "127.0.0.1", "", a.port)
        ida_ida.inf_set_dbg_no_store_path(True)
        entry = ida_ida.inf_get_start_ea()
        for ea in [entry] + a.bpt:
            print("add_bpt 0x%x:" % ea, idc.add_bpt(ea), flush=True)
        procs = ida_idd.procinfo_vec_t()
        print("get_processes:", ida_dbg.get_processes(procs), [(x.pid, x.name) for x in procs], flush=True)
        rc = ida_dbg.attach_process(procs[0].pid)
        print("attach_process rc:", rc, flush=True)
        names = {getattr(ida_dbg, n): n for n in dir(ida_dbg) if n.isupper() and n in (
            "PROCESS_STARTED", "PROCESS_EXITED", "THREAD_STARTED", "THREAD_EXITED", "BREAKPOINT", "STEP", "EXCEPTION",
            "LIB_LOADED", "INFORMATION", "PROCESS_ATTACHED", "PROCESS_DETACHED", "PROCESS_SUSPENDED", "TRACE_FULL", "LIB_UNLOADED")}
        names.update({getattr(ida_idd, n): n for n in ("PROCESS_STARTED", "PROCESS_EXITED", "THREAD_STARTED", "THREAD_EXITED",
            "BREAKPOINT", "STEP", "EXCEPTION", "LIB_LOADED", "LIB_UNLOADED", "INFORMATION", "PROCESS_ATTACHED", "PROCESS_DETACHED",
            "PROCESS_SUSPENDED") if hasattr(ida_idd, n)})
        reached_entry = False
        for i in range(a.events):
            code = ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY | ida_dbg.WFNE_SUSP, 15)
            ev = ida_dbg.get_debug_event()
            name = names.get(code, code)
            extra = ""
            if code == ida_idd.LIB_LOADED:
                extra = ev.modinfo().name
            describe("event %d %s %s" % (i, name, extra))
            if code in (ida_idd.PROCESS_EXITED, -1, 0) or ida_dbg.get_process_state() == ida_dbg.DSTATE_NOTASK:
                break
            if ida_dbg.get_ip_val() == (a.stop_at or entry):
                reached_entry = True
                break
            ida_dbg.continue_process()
        print("modules:", flush=True)
        for base, size, name in modules():
            print("   0x%x 0x%x %s" % (base, size, name), flush=True)
        print("segments:", flush=True)
        for s in [ida_segment.getnseg(i) for i in range(ida_segment.get_segm_qty())]:
            print("   0x%x-0x%x %s bitness=%d" % (s.start_ea, s.end_ea, ida_segment.get_segm_name(s), s.bitness), flush=True)
        if reached_entry:
            for i in range(a.steps):
                ida_dbg.step_into()
                code = ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY | ida_dbg.WFNE_SUSP, 15)
                describe("step %d %s" % (i, names.get(code, code)))
    finally:
        try:
            ida_dbg.exit_process()
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY, 5)
        except Exception as e:
            print("exit_process:", e)
        backend.kill()
        idapro.close_database(False)


if __name__ == "__main__":
    main()
