import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pefile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rsp import Rsp, libs, regs  # noqa: E402


def find_tail_jump(pe):
    """Return (address of the jmp after the last popad, its target) in the entry section."""
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    base = pe.OPTIONAL_HEADER.ImageBase
    for s in pe.sections:
        if s.VirtualAddress <= entry < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            data = s.get_data()
            start = entry - s.VirtualAddress
            best = None
            pos = data.find(b"\x61", start)
            while pos != -1 and pos < len(data):
                for off in range(1, 0x30):
                    j = pos + off
                    if j + 5 <= len(data) and data[j] == 0xE9:
                        rel = int.from_bytes(data[j + 1 : j + 5], "little", signed=True)
                        target = s.VirtualAddress + j + 5 + rel
                        if not (s.VirtualAddress <= target < s.VirtualAddress + s.Misc_VirtualSize) and 0 < target < pe.OPTIONAL_HEADER.SizeOfImage:
                            best = (base + s.VirtualAddress + j, base + target)
                            break
                if best:
                    return best
                pos = data.find(b"\x61", pos + 1)
            tail = data.find(bytes.fromhex("618d4424806a0039c475fa83ec80e9"), start)
            if tail != -1:
                j = tail + 14
                rel = int.from_bytes(data[j + 1 : j + 5], "little", signed=True)
                return (base + s.VirtualAddress + j, base + s.VirtualAddress + j + 5 + rel)
    return None


def read_mem(r, addr, size):
    out = bytearray()
    while len(out) < size:
        n = min(0x4000, size - len(out))
        rep = r.cmd("m%x,%x" % (addr + len(out), n))
        if not rep or rep.startswith("E"):
            out += b"\0" * n
        else:
            out += bytes.fromhex(rep)
    return bytes(out)


def compare(dump, truth_path, image_base):
    pe = pefile.PE(str(truth_path))
    res = []
    for s in pe.sections:
        raw = s.get_data()[: s.SizeOfRawData]
        mem = dump[s.VirtualAddress : s.VirtualAddress + len(raw)]
        same = sum(1 for a, b in zip(raw, mem) if a == b)
        res.append((s.Name.rstrip(b"\0").decode("latin1"), len(raw), same))
    return pe.OPTIONAL_HEADER.AddressOfEntryPoint + image_base, res


def main():
    p = argparse.ArgumentParser()
    p.add_argument("sample", type=Path)
    p.add_argument("--analyzer", required=True)
    p.add_argument("--root", required=True)
    p.add_argument("--guest", required=True)
    p.add_argument("--truth", type=Path)
    p.add_argument("--port", type=int, default=29100)
    p.add_argument("--max-stops", type=int, default=400)
    p.add_argument("--steps-after", type=int, default=0)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()

    pe = pefile.PE(str(a.sample), fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    tail = find_tail_jump(pe)
    result = {"sample": a.sample.name, "image_base": hex(image_base), "tail": tail and [hex(x) for x in tail]}
    if not tail:
        result["error"] = "no tail jump found"
        print(json.dumps(result))
        return

    log = open(a.out.with_suffix(".analyzer.log"), "w")
    proc = subprocess.Popen(
        [a.analyzer, "-d", "--gdb-arch", "auto", "--bind", "127.0.0.1", "--port", str(a.port), "--backend", "unicorn",
         "--network", "offline", "--root-mode", "ro", "-e", a.root, a.guest],
        stdout=log, stderr=subprocess.STDOUT)
    t0 = time.time()
    try:
        r = Rsp("127.0.0.1", a.port)
        r.cmd("qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386")
        r.cmd("?")
        v = regs(r, 32)
        result["initial"] = {"eip": hex(v["eip"]), "cs": hex(v["cs"])}
        actual_base = image_base
        for n, seg in libs(r):
            if n.lower().endswith(a.guest.lower().split("\\")[-1]):
                actual_base = seg - 0x1000
        result["loaded_base"] = hex(actual_base)
        delta = actual_base - image_base
        tail_addr, oep = tail[0] + delta, tail[1] + delta
        r.cmd("Z0,%x,1" % tail_addr)
        stops = 0
        bad = []
        outputs = []
        while stops < a.max_stops:
            stop = r.cmd("vCont;c", outputs)
            stops += 1
            if stop.startswith("W") or stop.startswith("X"):
                result["exited"] = stop
                break
            v = regs(r, 32)
            if v["cs"] != 0x23:
                bad.append(hex(v["eip"]))
            if v["eip"] == tail_addr:
                break
        result["stops"] = stops
        result["stops_not_cs23"] = bad[:5]
        if "exited" in result or v["eip"] != tail_addr:
            result["error"] = "tail jump not reached"
            return
        r.cmd("z0,%x,1" % tail_addr)
        r.cmd("vCont;s")
        v = regs(r, 32)
        result["after_step"] = {"eip": hex(v["eip"]), "cs": hex(v["cs"])}
        result["oep_ok"] = v["eip"] == oep
        dump = read_mem(r, actual_base, size_of_image)
        a.out.write_bytes(dump)
        if a.truth and a.truth.exists():
            truth_oep, secs = compare(dump, a.truth, actual_base)
            result["truth_oep"] = hex(truth_oep)
            result["truth_oep_ok"] = truth_oep == v["eip"]
            result["sections"] = [[n, size, same, round(100.0 * same / size, 2) if size else None] for n, size, same in secs]
        trace = []
        for i in range(a.steps_after):
            stop = r.cmd("vCont;s", outputs)
            if stop.startswith("W"):
                trace.append("exit")
                break
            v = regs(r, 32)
            trace.append("%x/%x" % (v["eip"], v["cs"]))
        if trace:
            result["steps_after_cs"] = sorted(set(x.split("/")[1] for x in trace))
            result["steps_after_last"] = trace[-3:]
    except Exception as e:
        result["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        result["seconds"] = round(time.time() - t0, 1)
        proc.kill()
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
