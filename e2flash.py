#!/usr/bin/env python3
"""e2flash: flash the official firmware onto a HANLinyue E2 Control page turner
from a Mac, over the USB cable. Python standard library only.

Typical use:
  python3 e2flash.py info          # is the remote connected? which firmware?
  python3 e2flash.py check         # read-only: which build is on the remote
  python3 e2flash.py flash kobo    # write the vendor's official KOBO firmware
  python3 e2flash.py reboot        # leave update mode without writing

The firmware is downloaded from the vendor's own server and checked against a
pinned SHA-512 before anything is written. Nothing from the vendor is bundled.

Update protocol (rebuilt for interoperability from the vendor's Windows updater),
one 64-byte HID report each way, report ID 0, little-endian:
  request : AA 55 lenL lenH | cmd 00 payload (XOR key 4E 61 BC 00) | crc16
            len = len(payload) + 2, crc16 = CRC-16/XMODEM over AA..payload
            after the XOR
  reply   : AA 55 lenL lenH | cmd status data... (bytes 4..63 XORed)
  C0 init   payload "app_dir_head\\0jl" + 00 + 00 -> upgrade_addr (file offset),
            upgrade_len, upgrade_eoffset (flash address), flash_alignsize
  C4 crc    addr, total_len, block_size (max 16 blocks) -> crc16 per 4 KB block
  C2 erase  addr, size code (1=256 B, 2=4 KB, 3=64 KB)
  C3 write  addr, len, data (41 bytes per packet)
  CA reboot no payload, no reply
Update order (same as the vendor): erase block 0, rewrite changed blocks
1..n-1, write block 0 from byte 0x20, then its first 0x20 bytes (header last),
then re-read every block CRC. The loader before upgrade_addr is never touched.
Normal mode is a USB serial port taking JSON: {"o":"JUMPBOOT"} enters update mode.
"""
import argparse
import ctypes
import glob
import hashlib
import json
import os
import select
import struct
import sys
import termios
import time
import tty
import urllib.request

__version__ = "1.0.0"

VID, PID = 0x4C4A, 0x4155
KEY = bytes([0x4E, 0x61, 0xBC, 0x00])
CRC_TAB = [0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
           0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF]
INIT_NAME = b"app_dir_head\x00jl"  # the vendor tool sends these 15 bytes of its string table
WRITE_CHUNK = 0x29
CRC_BATCH = 16
LOG = None

FW_URL = "http://obs.hanlinyue.mxlt.top/pc-simple/e2control/%s/jl_isd.bin"
FIRMWARE = {
    "kobo": ("kobo%E7%89%88", "Kobo e-readers (arrow keys)",
             "bc10be53331853e546636ac7e77d7d94f68b97ba2a95f47cea62766959cd856f"
             "e1210aac550ff52fdc20f795c311533aa7e9f4404c7e1e756e6cb45f25f086cc"),
    "touch": ("%E8%A7%A6%E6%91%B8%E6%9D%BF", "Android e-readers / Entertainment",
              "0e7db4c2a89fd6a9058d25ec8aaacbaa216566028d39df936faa678d914f957e"
              "90b26d3548fcc10350f051b2361130540d60a10f82ee48f7ccd131b48535c61b"),
    "scaled": ("%E7%BC%A9%E6%94%BE%E7%89%88", "Phones, tablets, PPT, short video, music",
               "72a2e0b0326ef31e8a75deeb840535d966be651b819398e2004f7b4a005f05a4"
               "cd88113f90ee3b8dfe835e58b51bbfaed0bd80fc56a8e1fbe24e76b61f4cc624"),
}
# Layout reported by the E2 Control bootloader; anything else is refused.
EXPECT = {"upgrade_addr": 0x3000, "upgrade_eoffset": 0x0, "flash_alignsize": 0x1000}
CACHE = os.path.expanduser("~/.cache/e2flash")


def log(*a):
    line = " ".join(str(x) for x in a)
    print(line, flush=True)
    if LOG:
        LOG.write(time.strftime("%H:%M:%S ") + line + "\n")
        LOG.flush()


# ---------------------------------------------------------------- protocol

def crc16(data):
    crc = 0
    for b in data:
        crc = ((crc << 4) & 0xFFFF) ^ CRC_TAB[(crc >> 12) ^ (b >> 4)]
        crc = ((crc << 4) & 0xFFFF) ^ CRC_TAB[(crc >> 12) ^ (b & 0x0F)]
    return crc


def xor(buf):
    return bytes(b ^ KEY[i & 3] for i, b in enumerate(buf))


def build(cmd, payload=b""):
    n = len(payload) + 2
    frame = bytes([0xAA, 0x55, n & 0xFF, n >> 8]) + xor(bytes([cmd, 0]) + payload)
    c = crc16(frame)
    frame += bytes([c & 0xFF, c >> 8])
    if len(frame) > 64:
        raise ValueError("packet too long: %d" % len(frame))
    return frame.ljust(64, b"\x00")


def parse(raw):
    if len(raw) == 65 and raw[0] == 0:
        raw = raw[1:]
    if len(raw) < 64:
        raise IOError("short reply: %d bytes" % len(raw))
    x = raw[:4] + xor(raw[4:64])
    if x[0:2] != b"\xAA\x55":
        raise IOError("bad reply header: %s" % raw[:16].hex())
    # vendor reads fields at fixed offsets from byte 6 and ignores the length
    return x[4], x[5], x[6:64], x


# ---------------------------------------------------------------- IOKit HID

class MacHid:
    def __init__(self):
        cf = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        io = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/IOKit.framework/IOKit")
        vp, i32, l = ctypes.c_void_p, ctypes.c_int32, ctypes.c_long
        for name, res, args in [
            ("CFStringCreateWithCString", vp, [vp, ctypes.c_char_p, ctypes.c_uint32]),
            ("CFNumberCreate", vp, [vp, ctypes.c_int, vp]),
            ("CFNumberGetValue", ctypes.c_bool, [vp, ctypes.c_int, vp]),
            ("CFDictionaryCreateMutable", vp, [vp, l, vp, vp]),
            ("CFDictionarySetValue", None, [vp, vp, vp]),
            ("CFSetGetCount", l, [vp]),
            ("CFSetGetValues", None, [vp, vp]),
            ("CFRelease", None, [vp]),
            ("CFRunLoopGetCurrent", vp, []),
            ("CFRunLoopRunInMode", i32, [vp, ctypes.c_double, ctypes.c_bool]),
        ]:
            f = getattr(cf, name); f.restype = res; f.argtypes = args
        for name, res, args in [
            ("IOHIDManagerCreate", vp, [vp, ctypes.c_uint32]),
            ("IOHIDManagerSetDeviceMatching", None, [vp, vp]),
            ("IOHIDManagerCopyDevices", vp, [vp]),
            ("IOHIDDeviceOpen", i32, [vp, ctypes.c_uint32]),
            ("IOHIDDeviceClose", i32, [vp, ctypes.c_uint32]),
            ("IOHIDDeviceGetProperty", vp, [vp, vp]),
            ("IOHIDDeviceSetReport", i32, [vp, ctypes.c_int, l, vp, l]),
            ("IOHIDDeviceRegisterInputReportCallback", None, [vp, vp, l, vp, vp]),
            ("IOHIDDeviceScheduleWithRunLoop", None, [vp, vp, vp]),
            ("IOHIDDeviceUnscheduleFromRunLoop", None, [vp, vp, vp]),
        ]:
            f = getattr(io, name); f.restype = res; f.argtypes = args
        self.cf, self.io = cf, io
        self.mode = ctypes.c_void_p.in_dll(cf, "kCFRunLoopDefaultMode").value
        self.dev = None
        self.queue = []
        CB = ctypes.CFUNCTYPE(None, vp, i32, vp, ctypes.c_int, ctypes.c_uint32,
                              ctypes.POINTER(ctypes.c_uint8), l)
        self._cb = CB(self._on_report)
        self._buf = (ctypes.c_uint8 * 1024)()

    def _str(self, s):
        return self.cf.CFStringCreateWithCString(None, s.encode(), 0x08000100)

    def _num(self, v):
        n = ctypes.c_int32(v)
        return self.cf.CFNumberCreate(None, 3, ctypes.byref(n))

    def _prop_int(self, dev, key):
        r = self.io.IOHIDDeviceGetProperty(dev, self._str(key))
        if not r:
            return None
        v = ctypes.c_int64(0)
        self.cf.CFNumberGetValue(r, 4, ctypes.byref(v))
        return v.value

    def find(self):
        mgr = self.io.IOHIDManagerCreate(None, 0)
        d = self.cf.CFDictionaryCreateMutable(
            None, 0,
            ctypes.addressof(ctypes.c_char.in_dll(self.cf, "kCFTypeDictionaryKeyCallBacks")),
            ctypes.addressof(ctypes.c_char.in_dll(self.cf, "kCFTypeDictionaryValueCallBacks")))
        self.cf.CFDictionarySetValue(d, self._str("VendorID"), self._num(VID))
        self.cf.CFDictionarySetValue(d, self._str("ProductID"), self._num(PID))
        self.io.IOHIDManagerSetDeviceMatching(mgr, d)
        s = self.io.IOHIDManagerCopyDevices(mgr)
        if not s:
            return []
        n = self.cf.CFSetGetCount(s)
        arr = (ctypes.c_void_p * n)()
        self.cf.CFSetGetValues(s, arr)
        out = []
        for dev in arr:
            out.append({"dev": dev,
                        "usage_page": self._prop_int(dev, "PrimaryUsagePage"),
                        "usage": self._prop_int(dev, "PrimaryUsage"),
                        "in": self._prop_int(dev, "MaxInputReportSize"),
                        "out": self._prop_int(dev, "MaxOutputReportSize")})
        return out

    def open(self, wait=0.0):
        end = time.time() + wait
        while True:
            devs = [d for d in self.find() if (d["out"] or 0) >= 64]
            if devs or time.time() >= end:
                break
            time.sleep(0.5)
        if len(devs) != 1:
            raise IOError("unable to open device: %d matching HID update interfaces "
                          "(is the remote in update mode?)" % len(devs))
        d = devs[0]
        log("hid: usage page 0x%x usage 0x%x in %s out %s" % (d["usage_page"] or 0, d["usage"] or 0, d["in"], d["out"]))
        rc = self.io.IOHIDDeviceOpen(d["dev"], 0)
        if rc != 0:
            raise IOError("IOHIDDeviceOpen failed: 0x%08x" % (rc & 0xFFFFFFFF))
        self.dev = d["dev"]
        self.io.IOHIDDeviceRegisterInputReportCallback(self.dev, ctypes.addressof(self._buf), len(self._buf), self._cb, None)
        self.io.IOHIDDeviceScheduleWithRunLoop(self.dev, self.cf.CFRunLoopGetCurrent(), self.mode)

    def _on_report(self, ctx, result, sender, rtype, rid, report, length):
        self.queue.append(bytes(report[:length]))

    def pump(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            self.cf.CFRunLoopRunInMode(self.mode, 0.005, True)

    def write(self, data64):
        buf = ctypes.create_string_buffer(bytes(data64), 64)
        rc = self.io.IOHIDDeviceSetReport(self.dev, 1, 0, ctypes.addressof(buf), 64)
        if rc != 0:
            raise IOError("IOHIDDeviceSetReport failed: 0x%08x" % (rc & 0xFFFFFFFF))

    def read(self, timeout=3.0):
        end = time.time() + timeout
        while not self.queue and time.time() < end:
            self.cf.CFRunLoopRunInMode(self.mode, 0.001, True)
        if not self.queue:
            raise IOError("no reply within %.1fs" % timeout)
        return self.queue.pop(0)

    def close(self):
        if self.dev:
            self.io.IOHIDDeviceUnscheduleFromRunLoop(self.dev, self.cf.CFRunLoopGetCurrent(), self.mode)
            self.io.IOHIDDeviceClose(self.dev, 0)
            self.dev = None


# ---------------------------------------------------------------- bootloader session

class Boot:
    def __init__(self, hid):
        self.h = hid

    def xfer(self, cmd, payload=b""):
        self.h.pump(0.002)
        self.h.queue.clear()
        self.h.write(build(cmd, payload))
        rcmd, status, data, _ = parse(self.h.read())
        if rcmd != cmd:
            raise IOError("reply to 0x%02X came back as 0x%02X" % (cmd, rcmd))
        return status, data

    def init(self):
        status, data = self.xfer(0xC0, INIT_NAME + b"\x00\x00")
        if status != 0:
            raise IOError("init: rsp error, status %d" % status)
        addr, ulen, eoff, align = struct.unpack_from("<IIII", data, 0)
        return {"upgrade_addr": addr, "upgrade_len": ulen, "upgrade_eoffset": eoff, "flash_alignsize": align}

    def crcs(self, addr, count, size):
        out = []
        while count:
            k = min(CRC_BATCH, count)
            status, data = self.xfer(0xC4, struct.pack("<III", addr, size * k, size))
            if status != 0:
                raise IOError("crc read at 0x%x: status %d" % (addr, status))
            out += list(struct.unpack_from("<%dH" % k, data, 0))
            addr += size * k
            count -= k
        return out

    def erase(self, addr, size):
        if size % 0x1000:
            raise ValueError("erase size 0x%x is not 4 KB aligned" % size)
        for a in range(addr, addr + size, 0x1000):
            status, _ = self.xfer(0xC2, struct.pack("<II", a, 2))
            if status != 0:
                raise IOError("erase reply %d at 0x%x" % (status, a))

    def write(self, addr, data):
        for i in range(0, len(data), WRITE_CHUNK):
            part = data[i:i + WRITE_CHUNK]
            status, _ = self.xfer(0xC3, struct.pack("<II", addr + i, len(part)) + part)
            if status != 0:
                raise IOError("write reply %d at 0x%x" % (status, addr + i))

    def reboot(self):
        try:
            self.h.write(build(0xCA))
        except IOError as err:
            # the remote resets before acknowledging the report
            log("reboot: %s (expected, the remote resets at once)" % err)



# ---------------------------------------------------------------- firmware files

def get_firmware(name, path=None):
    """Return the image bytes for a known build, downloading it if needed."""
    folder, _, sha = FIRMWARE[name]
    if path:
        raw = open(path, "rb").read()
    else:
        cached = os.path.join(CACHE, name + ".bin")
        if os.path.exists(cached):
            raw = open(cached, "rb").read()
        else:
            url = FW_URL % folder
            log("downloading %s firmware from the vendor: %s" % (name, url))
            with urllib.request.urlopen(url, timeout=60) as r:
                raw = r.read()
            if hashlib.sha512(raw).hexdigest() == sha:
                os.makedirs(CACHE, exist_ok=True)
                open(cached, "wb").write(raw)
    got = hashlib.sha512(raw).hexdigest()
    if got != sha:
        sys.exit("SHA-512 mismatch for the %s firmware (got %s...). Nothing was written.\n"
                 "The vendor may have published a new build; please open an issue." % (name, got[:16]))
    return raw


def blocks_of(raw, upgrade_addr, align):
    data = raw[upgrade_addr:]
    data += b"\xFF" * ((-len(data)) % align)
    blocks = [data[i:i + align] for i in range(0, len(data), align)]
    return blocks, [crc16(b) for b in blocks]


# ---------------------------------------------------------------- normal mode (serial)

def _open_serial(port):
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)
    time.sleep(0.3)
    termios.tcflush(fd, termios.TCIFLUSH)
    return fd


def _send(fd, obj, wait):
    os.write(fd, json.dumps(obj, separators=(",", ":")).encode())
    buf, end = b"", time.time() + wait
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                buf += os.read(fd, 4096)
            except OSError:
                break
    return buf


def _decode(buf):
    out, text, dec, i = [], buf.decode("utf-8", "replace"), json.JSONDecoder(), 0
    while True:
        i = text.find("{", i)
        if i < 0:
            return out
        try:
            obj, i = dec.raw_decode(text, i)
            out.append(obj)
        except ValueError:
            i += 1


def query(port, fields=("firmware", "model", "battery")):
    """Ask a remote in normal mode for its status. Read-only."""
    try:
        fd = _open_serial(port)
    except OSError:
        return {}
    got = {}
    try:
        _send(fd, {"o": "get", "t": "firmware"}, 0.8)  # the first command after opening is dropped
        for t in fields:
            for _ in range(2):
                for m in _decode(_send(fd, {"o": "get", "t": t}, 0.8)):
                    if m.get("o") == "getresult" and "t" in m:
                        got[m["t"]] = m.get("v")
                if t in got:
                    break
                time.sleep(0.15)
    finally:
        os.close(fd)
    return got


def find_remote():
    for port in sorted(glob.glob("/dev/cu.usbmodem*")):
        status = query(port, ("firmware", "model"))
        if status:
            return port, status
    return None, {}


def hid_present():
    return any((d["out"] or 0) >= 64 for d in MacHid().find())


def enter_update_mode():
    """Return an open bootloader session; send JUMPBOOT first if needed."""
    if hid_present():
        log("remote is already in update mode")
    else:
        port, status = find_remote()
        if not port:
            sys.exit("No E2 Control found. Connect it with a USB data cable, switch it on, and retry.")
        log("found remote on %s (firmware %s)" % (port, status.get("firmware")))
        for attempt in range(2):
            fd = _open_serial(port)
            try:
                _send(fd, {"o": "get", "t": "firmware"}, 0.8)
                _send(fd, {"o": "get", "t": "firmware"}, 0.8)
                _send(fd, {"o": "JUMPBOOT"}, 0.5)
            except OSError:
                pass  # the port can vanish while the remote restarts
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass
            end = time.time() + 8
            while time.time() < end and not hid_present():
                time.sleep(0.5)
            if hid_present():
                break
            log("remote did not switch to update mode, retrying")
    h = MacHid()
    h.open(wait=5)
    return h, Boot(h)


def init_checked(b, force):
    info = b.init()
    log("bootloader: image offset 0x%x, flash offset 0x%x, block 0x%x" %
        (info["upgrade_addr"], info["upgrade_eoffset"], info["flash_alignsize"]))
    odd = {k: v for k, v in EXPECT.items() if info[k] != v}
    if odd and not force:
        raise SystemExit("Unexpected bootloader layout %s; this may not be an E2 Control. "
                         "Nothing was written. Run `reboot` to leave update mode." %
                         {k: hex(info[k]) for k in odd})
    if info["flash_alignsize"] % 0x1000 or not info["flash_alignsize"]:
        raise SystemExit("Unsupported block size 0x%x. Nothing was written." % info["flash_alignsize"])
    return info


def identify(b, info, images):
    """Compare the remote's block CRCs with each known build. Read-only."""
    align, eoff = info["flash_alignsize"], info["upgrade_eoffset"]
    longest = max(len(blocks_of(raw, info["upgrade_addr"], align)[1]) for raw in images.values())
    dev = b.crcs(eoff, longest, align)
    scores = {}
    for name, raw in images.items():
        fcrc = blocks_of(raw, info["upgrade_addr"], align)[1]
        scores[name] = (sum(x == y for x, y in zip(fcrc, dev)), len(fcrc))
    return dev, scores


def report_scores(scores):
    for name, (same, n) in sorted(scores.items(), key=lambda kv: -kv[1][0]):
        log("  %-7s %2d of %2d blocks match%s" % (name, same, n, "  <- installed" if same == n else ""))


# ---------------------------------------------------------------- commands

def cmd_selftest(_):
    assert crc16(b"123456789") == 0x31C3, hex(crc16(b"123456789"))
    p = build(0xC0, INIT_NAME + b"\x00\x00")
    assert p[:6] == bytes([0xAA, 0x55, 19, 0, 0xC0 ^ 0x4E, 0x00 ^ 0x61])
    c = crc16(p[:4 + 19])
    assert p[4 + 19:4 + 21] == bytes([c & 0xFF, c >> 8])
    body = bytes([0xC0, 0]) + struct.pack("<IIII", 0x3000, 0x36000, 0x3000, 0x1000)
    raw = bytes([0xAA, 0x55, len(body), 0]) + xor(body.ljust(60, b"\x00"))
    rc, st, data, _ = parse(raw)
    assert (rc, st) == (0xC0, 0) and struct.unpack_from("<IIII", data) == (0x3000, 0x36000, 0x3000, 0x1000)
    assert build(0xCA)[:6] == bytes([0xAA, 0x55, 2, 0, 0xCA ^ 0x4E, 0x61])
    print("selftest ok: crc16/xmodem, request framing, reply decoding")


def cmd_info(_):
    port, status = find_remote()
    if port:
        print("E2 Control in normal mode on %s: %s" % (port, json.dumps(status)))
    elif hid_present():
        print("E2 Control is in update mode. Run `flash <build>` to finish an update, or `reboot`.")
    else:
        print("No E2 Control found. Use a USB data cable and switch the remote on.")


def cmd_check(a):
    images = {n: get_firmware(n) for n in FIRMWARE}
    h, b = enter_update_mode()
    try:
        info = init_checked(b, a.force)
        _, scores = identify(b, info, images)
        log("installed firmware compared with the official builds:")
        report_scores(scores)
        log("rebooting to normal mode (nothing was written)")
        b.reboot()
    finally:
        h.close()


def cmd_reboot(_):
    if not hid_present():
        sys.exit("The remote is not in update mode; nothing to do.")
    h = MacHid()
    h.open(wait=2)
    try:
        Boot(h).reboot()
        log("reboot sent")
    finally:
        h.close()


def cmd_flash(a):
    images = {n: get_firmware(n) for n in FIRMWARE}
    raw = get_firmware(a.build, a.file) if a.file else images[a.build]
    h, b = enter_update_mode()
    try:
        info = init_checked(b, a.force)
        addr, eoff, align = info["upgrade_addr"], info["upgrade_eoffset"], info["flash_alignsize"]
        dcrc, scores = identify(b, info, images)
        log("installed firmware compared with the official builds:")
        report_scores(scores)
        if max(s for s, _ in scores.values()) < 8 and not a.force:
            raise SystemExit("The installed firmware matches none of the known E2 Control builds, so this "
                             "may be a different device. Nothing was written. Run `reboot` to leave update mode.")
        blocks, fcrc = blocks_of(raw, addr, align)
        dcrc = dcrc[:len(blocks)]
        if dcrc == fcrc:
            log("the %s firmware is already installed; nothing to write" % a.build)
            b.reboot()
            return
        if not a.yes:
            print("\nAbout to write the official %s firmware (%s): %d blocks of 4 KB.\n"
                  "Keep the cable connected until it says 'update ok'. If it is interrupted,\n"
                  "run the same command again: the remote waits in update mode." %
                  (a.build, FIRMWARE[a.build][1], len(blocks)))
            if input("Type YES to write: ").strip() != "YES":
                log("cancelled; rebooting to normal mode, nothing was written")
                b.reboot()
                return
        todo = [i for i in range(1, len(blocks)) if dcrc[i] != fcrc[i]]
        log("erasing block 0 (the header is written last)")
        b.erase(eoff, align)
        for n, i in enumerate(todo, 1):
            dst = eoff + i * align
            log("block %2d  %2d/%d" % (i, n, len(todo)))
            b.erase(dst, align)
            b.write(dst, blocks[i])
        log("block  0  header")
        b.write(eoff + 0x20, blocks[0][0x20:])
        b.write(eoff, blocks[0][:0x20])
        vcrc = b.crcs(eoff, len(blocks), align)
        bad = [i for i, (x, y) in enumerate(zip(vcrc, fcrc)) if x != y]
        if bad:
            log("update failed: CRC mismatch in blocks %s. The remote stays in update mode; "
                "run the same command again." % bad)
            sys.exit(2)
        log("update ok: all %d blocks verified" % len(blocks))
        b.reboot()
        log("remote restarted. Unplug it, choose the mode with the side switch and pair it again.")
    finally:
        h.close()


def main():
    global LOG
    if sys.platform != "darwin":
        sys.exit("This tool runs on macOS only (it talks to USB through IOKit).")
    p = argparse.ArgumentParser(prog="e2flash", description="Flash official firmware onto a HANLinyue E2 Control from a Mac.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--log", help="also append the output to this file")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("info", help="show whether the remote is connected and its firmware version")
    s = sub.add_parser("check", help="read-only: which official build is installed")
    s.add_argument("--force", action="store_true", help=argparse.SUPPRESS)
    s = sub.add_parser("flash", help="write an official build")
    s.add_argument("build", choices=sorted(FIRMWARE), help="kobo, touch or scaled")
    s.add_argument("--file", help="use a local jl_isd.bin instead of downloading (must match the pinned SHA-512)")
    s.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    s.add_argument("--force", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("reboot", help="leave update mode without writing")
    sub.add_parser("selftest", help="offline protocol self-test")
    a = p.parse_args()
    if not a.cmd:
        p.print_help()
        return
    if a.log:
        LOG = open(a.log, "a")
    {"info": cmd_info, "check": cmd_check, "flash": cmd_flash, "reboot": cmd_reboot,
     "selftest": cmd_selftest}[a.cmd](a)


if __name__ == "__main__":
    main()
