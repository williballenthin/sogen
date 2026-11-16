# Debugging WOW64 processes through the GDB stub

This folder holds the notes, scripts and logs for the WOW64 GDB stub change in this branch. It is not part of the change and must be removed before an upstream pull request.

## The problem

`--gdb-arch auto` sends the i386 target description for a WOW64 process, and IDA attaches as a 32-bit debugger. Before the change, the stub always sent the live registers of vCPU 0. A WOW64 thread runs 64-bit code (cs=0x33) before its first 32-bit instruction, during each module load, and in the wow64cpu part of each 32-bit syscall. At these points the client got 64-bit registers cut to 32 bits.

Measured on upstream 08d299de with `probe32.exe` (`logs/rsp-auto-probe32.txt`, `logs/ida-auto-probe32.txt`):

- The initial stop is at eip=0xe8b90, cs=0x33, which is the 64-bit `LdrInitializeThunk` cut to 32 bits. IDA shows `db 0` in its `MEMORY` segment.
- All 14 library stops before the entry point are in 64-bit ntdll, at cut addresses.
- The library list includes 64-bit ntdll, win32u and the wow64 modules at 0x7ff0.... IDA has no segments for them.
- `qGetTIBAddr` gives TEB64.
- A step into a 32-bit syscall shows about 40 steps of 64-bit code as 32-bit code.
- 32-bit breakpoints, 32-bit steps and debug strings work.

The deps/sogen pin of the Malware Analysis add-on (8b4a8931) has the same behavior (`logs/ida-auto-probe32-pin.txt`).

IDA 9.5 does not accept the amd64 description for a 32-bit database. `attach_process` returns -1 without a message, also after `inf_set_64bit(True)`. Thus a fix must be in the stub.

## Options

A. A 32-bit view in the stub, as a 32-bit Windows debugger sees a WOW64 thread. This branch implements it in `src/windows-gdb-stub/win_gdb_stub_handler.hpp`. While cs is not a 32-bit segment, the general registers come from `capture_wow64_thread_context` and go to `apply_wow64_thread_context`, which use the `WOW64_CPURESERVED` copy. A single step continues through 64-bit code until the thread is in 32-bit code again. Only I386 modules are listed and signaled. `qGetTIBAddr` gives TEB32. 64-bit processes use the old code path.

B. Only the register part of A. Stops then show 32-bit addresses, but the 64-bit modules, the extra library stops and the 64-bit steps in syscalls stay.

C. Hold back each stop until the thread runs 32-bit code. The stop location changes, a thread that waits in 64-bit code never stops, and steps and interrupts stay wrong.

D. The amd64 description with a 64-bit database. IDA refuses it.

E. Changes in the client (IDA or the add-on), for example to ignore stops with cs=0x33. This cannot fix the register values that the client reads.

## Results of option A

`logs/rsp-proto-probe32.txt` and `logs/ida-proto-probe32.txt`:

| | before | option A |
|---|---|---|
| initial suspend | 0xe8b90, cs=0x33, `MEMORY` | 0x7007b8e0 in ntdll32, cs=0x23 |
| library stops before the entry | 14, in 64-bit code | 5, at the ntdll32 syscall return 0x700794ac |
| modules | 32-bit and 64-bit | the executable and SysWOW64 modules |
| TEB | 0x2b0000 (TEB64) | 0x2b2000 (TEB32) |
| step into `NtDelayExecution` | about 40 steps in 64-bit code | `jmp far` in wow64cpu, then `retn 8` in ntdll32 |
| probe64.exe | | no change |

A write of esi at a stop in 64-bit code (`P6`) reads back correctly and is still there at the next stop. That stop was also a library stop, so the check does not show that the value got to 32-bit execution.

## UPX test with 32-bit samples

`upx32-samples.txt` lists 10 UPX-packed 32-bit EXEs from VirusTotal (`type:peexe packer:upx NOT tag:64bits`). Three of them use a modified UPX that `upx -d` refuses. `upx -d` (UPX 5.3.0) gives the reference OEP and sections for the other seven.

`unpack_gdb.py` unpacks one sample through raw RSP. It finds the `popad ... jmp` tail of the UPX stub, sets `Z0` on the jmp, continues, steps once and reads the image with `m` packets. `run_all.sh` runs it on all samples.

With this branch (`logs/upx32-rsp-proto.jsonl`), 7 of 10 samples get to the OEP in 3 to 8 s. The 5 samples that have a `upx -d` reference stop at the same OEP, and their code sections are equal to the `upx -d` output. The differences are in the resolved IAT, `.rsrc` and `.reloc`. All stops have cs=0x23, and 200 steps after the OEP stay in 32-bit code. The other 3 samples stop with hard error 0xC0000135, because the root has no ICMP.DLL, MSVBVM60.DLL or LZ32.DLL.

The add-on pin 8b4a8931 (`logs/upx32-rsp-pin.jsonl`) also gets to 6 OEPs with a breakpoint on a known address. Its initial stop is in 64-bit code, and it gives 9 to 10 more stops per sample at a 64-bit address cut to 32 bits.

The IDA unpacker test (`ida_batch.sh`, `logs/upx32-ida.jsonl`) runs `unpack_one.py -b sogen` of the Malware Analysis add-on with the heuristics `jumps-other-section` and `run-to-exit-point`. `jumps-other-section` sets one range breakpoint (`Z1,401000,15000`) on the sections that do not contain the entry point. Before commit 7491e3b1, the stub sent `T05` without a stop reason. IDA then reported the stop at the OEP as an unexpected SIGTRAP and not as a breakpoint, and the heuristic found no OEP. 7491e3b1 adds `swbreak`, `hwbreak`, `watch`, `rwatch` and `awatch` to the stop reply. This part is not specific to WOW64.

| heuristic | this branch | pin 8b4a8931 |
|---|---|---|
| `jumps-other-section` | 7 of 7 runnable samples stop at a jump to another section. 6 OEPs are equal to the target of the UPX tail jump. ffbb5c56 stops at 0x4287d1 in UPX0, and its UPX tail jumps to 0x42b818 in UPX1. | 0 of 10. Each OEP stop is an EXCEPTION. |
| `run-to-exit-point` | 3 OEPs from the heuristic, all correct | 3 OEPs from the heuristic, all wrong (0x41c38b, 0x4349fc, 0x8b10eb) |

The `run-to-exit-point` failures do not come from the stub. The two builds have the same failures:

- 1ef6c1a4 runs to ExitProcess.
- 8b0d66f1 stops when the emulator does not support NtQueryInformationProcess class 0x3D.
- ffbb5c56 ends at a LIB_LOADED event, after one-click-debugging fails to read a 0-byte export array of profapi.dll.

Open items:

- The step loop stops after 1,000,000 instructions and does not use the scheduler. A step over a syscall that waits for a different thread is not tested.
- Processes with more than one thread are not tested. x87 and XMM registers always come from the live CPU.
- The stub reports no guest exceptions for any process. It always sends signal 5.
- Read and write watchpoints also trigger on accesses from 64-bit wow64 code. Such stops show the saved 32-bit context.
- `capture_wow64_thread_context` and `apply_wow64_thread_context` are not in 8b4a8931.

## How to reproduce

Build the probe with zig:

```
uvx --from ziglang python -m ziglang cc -target x86-windows-gnu -O1 -o probe32.exe probe32.c
uvx --from ziglang python -m ziglang cc -target x86_64-windows-gnu -O1 -o probe64.exe probe32.c
```

The emulation root is the "Windows 2025 Emulation Root" artifact of upstream CI run 43910395350. An older root fails on 08d299de with "Failed to read apisetschema.dll". Put the probes in `root/filesys/c/`.

```
analyzer -d --gdb-arch auto --bind 127.0.0.1 --port 28971 --backend unicorn \
  --network offline --root-mode ro -e root 'c:\probe32.exe' &
python3 rsp.py --port 28971 --bits 32 --entry 0x401420 --steps 12
```

`ida_attach.py` runs the attach sequence of the add-on in idalib. It sets breakpoints, logs each debug event and steps from a stop address. Load the probe in IDA first and save the database.

```
IDADIR=... IDAUSR=... python ida_attach.py probe32.exe --port 28972 \
  --analyzer-cmd "analyzer -d --gdb-arch auto --bind 127.0.0.1 --port 28972 ... 'c:\probe32.exe'" \
  --bpt 0x70079560 --stop-at 0x70079560 --steps 10
```

0x70079560 is `NtDelayExecution` in the 32-bit ntdll of this root.
