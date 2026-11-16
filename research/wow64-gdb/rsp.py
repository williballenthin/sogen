import argparse
import re
import socket
import struct
import subprocess
import sys
import time


class Rsp:
    def __init__(self, host, port):
        for _ in range(100):
            try:
                self.s = socket.create_connection((host, port))
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("cannot connect")
        self.buf = b""

    def _read_packet(self):
        while True:
            while b"$" not in self.buf or b"#" not in self.buf[self.buf.index(b"$") :] or len(self.buf) < self.buf.index(b"#", self.buf.index(b"$")) + 3:
                chunk = self.s.recv(65536)
                if not chunk:
                    raise EOFError
                self.buf += chunk
            start = self.buf.index(b"$")
            end = self.buf.index(b"#", start)
            data = self.buf[start + 1 : end]
            self.buf = self.buf[end + 3 :]
            self.s.sendall(b"+")
            text = data.decode("latin1")
            out = []
            i = 0
            while i < len(text):
                if text[i] == "*":
                    out.append(out[-1] * (ord(text[i + 1]) - 29))
                    i += 2
                else:
                    out.append(text[i])
                    i += 1
            return "".join(out)

    def cmd(self, payload, outputs=None):
        csum = sum(payload.encode("latin1")) & 0xFF
        self.s.sendall(b"$" + payload.encode("latin1") + b"#%02x" % csum)
        while True:
            reply = self._read_packet()
            if reply.startswith("O") and reply != "OK" and outputs is not None:
                outputs.append(bytes.fromhex(reply[1:]).decode("latin1", "replace"))
                continue
            return reply


def xfer(r, obj, annex):
    out = ""
    off = 0
    while True:
        rep = r.cmd("qXfer:%s:read:%s:%x,%x" % (obj, annex, off, 0x3000))
        out += rep[1:]
        off += len(rep) - 1
        if rep.startswith("l"):
            return out


X86_NAMES = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"]
X64_NAMES = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"] + ["r%d" % i for i in range(8, 16)] + ["rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"]


def regs(r, bits):
    g = r.cmd("g")
    out = {}
    if bits == 32:
        for i, n in enumerate(X86_NAMES):
            out[n] = struct.unpack("<I", bytes.fromhex(g[i * 8 : i * 8 + 8]))[0]
        out["pc"] = out["eip"]
    else:
        pos = 0
        for n in X64_NAMES:
            size = 8 if n.startswith("r") and n != "rflags" else 4
            if n == "eflags":
                size = 4
            out[n] = int.from_bytes(bytes.fromhex(g[pos : pos + size * 2]), "little")
            pos += size * 2
        out["pc"] = out["rip"]
    return out


def libs(r):
    xml = xfer(r, "libraries", "")
    return [(n, int(a, 16)) for n, a in re.findall(r'<library name="([^"]*)"><segment address="0x([0-9a-fA-F]+)"', xml)]


def where(pc, libraries):
    best = None
    for n, seg in libraries:
        base = seg - 0x1000
        if base <= pc and (best is None or base > best[1]):
            best = (n, base)
    if best and pc - best[1] < 0x400000:
        return "%s+0x%x" % (best[0].split("\\")[-1], pc - best[1])
    return "?"


def describe(r, bits, label, libraries):
    v = regs(r, bits)
    pc = v["pc"]
    print("%-28s pc=0x%x cs=0x%x sp=0x%x  in %s" % (label, pc, v["cs"], v["esp" if bits == 32 else "rsp"], where(pc, libraries)))
    return v


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=28960)
    p.add_argument("--bits", type=int, choices=[32, 64], required=True)
    p.add_argument("--entry", type=lambda x: int(x, 0), required=True)
    p.add_argument("--steps", type=int, default=12)
    p.add_argument("--continues", type=int, default=0)
    a = p.parse_args()

    r = Rsp("127.0.0.1", a.port)
    print("qSupported:", r.cmd("qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;xmlRegisters=i386"))
    tdesc = xfer(r, "features", "target.xml")
    print("target.xml architecture:", re.findall(r"<architecture>([^<]*)", tdesc), "osabi:", re.findall(r"<osabi>([^<]*)", tdesc))
    print("?:", r.cmd("?"))
    libraries = libs(r)
    print("libraries at first stop:")
    for n, s in libraries:
        print("   0x%x %s" % (s - 0x1000, n))
    describe(r, a.bits, "initial stop", libraries)
    tid = r.cmd("qC")
    print("qC:", tid, "TIB:", r.cmd("qGetTIBAddr:%s" % tid[2:]))

    print("Z0 entry:", r.cmd("Z0,%x,1" % a.entry))
    outputs = []
    for i in range(40):
        stop = r.cmd("vCont;c", outputs)
        libraries = libs(r)
        v = describe(r, a.bits, "stop %d %s" % (i, stop[:20]), libraries)
        if stop.startswith("W") or v["pc"] == a.entry:
            break
    print("debug output:", outputs)
    for i in range(a.steps):
        stop = r.cmd("vCont;s")
        if stop.startswith("W"):
            print("exit", stop)
            return
        describe(r, a.bits, "step %d" % i, libraries)
    for i in range(a.continues):
        stop = r.cmd("vCont;c", outputs)
        if stop.startswith("W"):
            print("exit", stop)
            break
        libraries = libs(r)
        describe(r, a.bits, "cont %d %s" % (i, stop[:20]), libraries)
    print("debug output:", outputs)


if __name__ == "__main__":
    main()
