#!/usr/bin/env python3
# k5flash — Quansheng UV-K5 firmware flasher
# Copyright (c) 2026 carrierprincess
# MIT License — do whatever you want, just keep this notice.

import sys
import struct
import math
import time
import serial
from itertools import cycle

OBFUS = b"\x16\x6c\x14\xe6\x2e\x91\x0d\x40\x21\x35\xd5\x40\x13\x03\xe9\x80"

# fw-pack.py obfuscation key (128 bytes)
FW_PACK_KEY = bytes([
    0x47, 0x22, 0xC0, 0x52, 0x5D, 0x57, 0x48, 0x94, 0xB1, 0x60, 0x60, 0xDB, 0x6F, 0xE3, 0x4C, 0x7C,
    0xD8, 0x4A, 0xD6, 0x8B, 0x30, 0xEC, 0x25, 0xE0, 0x4C, 0xD9, 0x00, 0x7F, 0xBF, 0xE3, 0x54, 0x05,
    0xE9, 0x3A, 0x97, 0x6B, 0xB0, 0x6E, 0x0C, 0xFB, 0xB1, 0x1A, 0xE2, 0xC9, 0xC1, 0x56, 0x47, 0xE9,
    0xBA, 0xF1, 0x42, 0xB6, 0x67, 0x5F, 0x0F, 0x96, 0xF7, 0xC9, 0x3C, 0x84, 0x1B, 0x26, 0xE1, 0x4E,
    0x3B, 0x6F, 0x66, 0xE6, 0xA0, 0x6A, 0xB0, 0xBF, 0xC6, 0xA5, 0x70, 0x3A, 0xBA, 0x18, 0x9E, 0x27,
    0x1A, 0x53, 0x5B, 0x71, 0xB1, 0x94, 0x1E, 0x18, 0xF2, 0xD6, 0x81, 0x02, 0x22, 0xFD, 0x5A, 0x28,
    0x91, 0xDB, 0xBA, 0x5D, 0x64, 0xC6, 0xFE, 0x86, 0x83, 0x9C, 0x50, 0x1C, 0x73, 0x03, 0x11, 0xD6,
    0xAF, 0x30, 0xF4, 0x2C, 0x77, 0xB2, 0x7D, 0xBB, 0x3F, 0x29, 0x28, 0x57, 0x22, 0xD6, 0x92, 0x8B,
])

# ── 24-bit color helpers ─────────────────────────────────────────────

def rgb(r, g, b):
    return f"\033[38;2;{r};{g};{b}m"

def rgb_bg(r, g, b):
    return f"\033[48;2;{r};{g};{b}m"

RST   = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"

# palette
C_LOGO    = rgb(180, 140, 255)    # soft purple
C_OK      = rgb(100, 220, 160)    # mint green
C_ERR     = rgb(255, 90, 90)      # coral red
C_WARN    = rgb(255, 200, 80)     # amber
C_INFO    = rgb(130, 160, 210)    # steel blue
C_DIM     = rgb(80, 80, 100)      # muted grey
C_ACCENT  = rgb(200, 160, 255)    # light purple
C_WHITE   = rgb(220, 220, 230)    # off-white
C_CYAN    = rgb(100, 220, 240)    # bright cyan

LOGO = f"""
  {C_LOGO}{BOLD}▐ {C_ACCENT}█▄▀ █▀ █▀▀ █   ▄▀█ █▀ █ █
  {C_LOGO}{BOLD}▐ {C_ACCENT}█ █ ▄█ █▀  █▄▄ █▀█ ▄█ █▀█{RST}
  {C_DIM}▐ quansheng uv-k5 flasher{RST}
"""

def status(icon, color, msg):
    print(f"  {color}{icon}{RST} {C_WHITE}{msg}{RST}")

def phase(msg):
    print(f"\n  {C_ACCENT}{BOLD}▸ {msg}{RST}")

def progress_bar(page, total, t_start):
    pct = (page + 1) / total
    width = 40
    filled = int(width * pct)
    empty = width - filled

    # gradient from purple to cyan across the bar
    bar = ""
    for i in range(filled):
        t = i / max(width - 1, 1)
        r = int(180 * (1 - t) + 100 * t)
        g = int(140 * (1 - t) + 220 * t)
        b = int(255 * (1 - t) + 240 * t)
        bar += f"{rgb_bg(r, g, b)} {RST}"

    bar += f"{rgb_bg(30, 30, 40)}{' ' * empty}{RST}"

    elapsed = time.time() - t_start
    bytes_done = (page + 1) * 256
    rate = bytes_done / elapsed if elapsed > 0 else 0

    if rate >= 1024:
        rate_str = f"{rate/1024:.1f} KB/s"
    else:
        rate_str = f"{rate:.0f} B/s"

    pct_str = f"{int(pct * 100):3d}%"
    pages_str = f"{page+1}/{total}"

    print(f"\r  {bar} {C_ACCENT}{pct_str}{RST} {C_DIM}{pages_str}{RST} {C_CYAN}{rate_str}{RST}  ", end='', flush=True)

# ── protocol ─────────────────────────────────────────────────────────

def xor_obfus(data, off=0, size=None):
    buf = bytearray(data)
    if size is None:
        size = len(buf) - off
    for i in range(size):
        buf[off + i] ^= OBFUS[i % len(OBFUS)]
    return buf

def crc16_xmodem(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
            crc &= 0xFFFF
    return crc

def make_packet(msg_data):
    msg_len = len(msg_data)
    if msg_len % 2:
        msg_data = msg_data + b'\x00'
        msg_len += 1
    buf = bytearray(8 + msg_len)
    struct.pack_into('<H', buf, 0, 0xCDAB)
    struct.pack_into('<H', buf, 2, msg_len)
    buf[4:4+len(msg_data)] = msg_data
    crc = crc16_xmodem(buf[4:4+msg_len])
    struct.pack_into('<H', buf, 4+msg_len, crc)
    struct.pack_into('<H', buf, 6+msg_len, 0xBADC)
    buf = xor_obfus(buf, 4, msg_len + 2)
    return bytes(buf)

def parse_packet(buf):
    idx = buf.find(b'\xab\xcd')
    if idx == -1:
        return None, buf[-1:] if buf.endswith(b'\xab') else b''
    if len(buf) - idx < 8:
        return None, buf[idx:]
    msg_len = struct.unpack_from('<H', buf, idx + 2)[0]
    pack_end = idx + 6 + msg_len
    if len(buf) < pack_end + 2:
        return None, buf[idx:]
    footer = struct.unpack_from('<H', buf, pack_end)[0]
    if footer != 0xBADC:
        return None, buf[idx+2:]
    pkt = bytearray(buf[idx:pack_end+2])
    pkt = xor_obfus(pkt, 4, msg_len + 2)
    msg = bytes(pkt[4:4+msg_len-2])
    return msg, buf[pack_end+2:]

def get_u16(data, off=0):
    return struct.unpack_from('<H', data, off)[0]

MSG_DEV_INFO   = 0x0518
MSG_BL_VER     = 0x0530
MSG_PROG_FW    = 0x0519
MSG_PROG_RESP  = 0x051A

# ── packed firmware detection ────────────────────────────────────────

def unpack_firmware(data):
    """Detect and unpack fw-pack.py obfuscated firmware. Returns (raw_bytes, was_packed, version)."""
    # packed format: XOR(plain[:0x2000] + 16-byte version + plain[0x2000:]) + 2-byte CRC
    # minimum: 2-byte CRC + at least 1 byte of payload
    if len(data) < 3:
        return data, False, None

    # verify trailing CRC (little-endian, byte-swapped by fw-pack)
    payload = data[:-2]
    trail = data[-2:]
    crc = crc16_xmodem(payload)
    crc_bytes = bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    if trail != crc_bytes:
        return data, False, None

    # CRC matches — deobfuscate
    plain = bytes(a ^ b for a, b in zip(payload, cycle(FW_PACK_KEY)))

    # extract version string at 0x2000 and strip it (if firmware is large enough)
    if len(plain) >= 0x2010:
        ver_raw = plain[0x2000:0x2010]
        ver_str = ver_raw.rstrip(b'\x00').decode('ascii', errors='replace')
        raw = plain[:0x2000] + plain[0x2010:]
    else:
        ver_str = None
        raw = plain

    # sanity: ARM vector table — SP should point to SRAM (0x2000xxxx)
    if len(raw) >= 4:
        sp = struct.unpack_from('<I', raw, 0)[0]
        if (sp >> 16) != 0x2000:
            return data, False, None

    return raw, True, ver_str

# ── flash ────────────────────────────────────────────────────────────

def flash(port, fw_path):
    print(LOGO)

    with open(fw_path, 'rb') as f:
        fw_data = f.read()

    fw_data, was_packed, pack_ver = unpack_firmware(fw_data)

    fw_size = len(fw_data)
    page_count = math.ceil(fw_size / 256)

    status("◆", C_INFO, f"Firmware  {C_ACCENT}{fw_path}")
    if was_packed:
        status("◆", C_WARN, f"Format    {C_ACCENT}packed (auto-unpacked)")
        status("◆", C_WARN, f"Version   {C_ACCENT}{pack_ver}")
    else:
        status("◆", C_INFO, f"Format    {C_ACCENT}raw binary")
    status("◆", C_INFO, f"Size      {C_ACCENT}{fw_size}{C_WHITE} bytes ({page_count} pages)")
    status("◆", C_INFO, f"Port      {C_ACCENT}{port}")

    ser = serial.Serial(port, 38400, timeout=0.005)
    ser.reset_input_buffer()

    # ── phase 1: bootloader detection ──
    phase("Listening for bootloader beacon...")
    buf = b''
    beacon_count = 0
    bl_version = "?"

    deadline = time.time() + 15
    while time.time() < deadline:
        chunk = ser.read(256)
        if chunk:
            buf += chunk

        while True:
            msg, buf = parse_packet(buf)
            if msg is None:
                break
            msg_type = get_u16(msg, 0)
            if msg_type == MSG_DEV_INFO:
                beacon_count += 1
                if beacon_count == 1:
                    uid = msg[4:20]
                    ver_end = msg.find(b'\x00', 20, 36)
                    if ver_end == -1:
                        ver_end = 36
                    bl_version = msg[20:ver_end].decode('ascii', errors='replace')
                    uid_hex = ' '.join(f'{b:02x}' for b in uid)
                    status("›", C_DIM, f"UID        {C_DIM}{uid_hex}")
                    status("›", C_DIM, f"Bootloader {C_CYAN}{bl_version}")
                if beacon_count >= 5:
                    break
        if beacon_count >= 5:
            break

    if beacon_count < 5:
        status("✗", C_ERR, "Could not detect bootloader. Is radio in DFU mode?")
        print(f"\n  {C_DIM}(hold PTT + power on → white LED){RST}\n")
        ser.close()
        return False

    status("✓", C_OK, "Bootloader detected")

    # ── phase 2: handshake ──
    phase("Handshaking...")
    handshake_count = 0

    deadline = time.time() + 10
    while time.time() < deadline and handshake_count < 3:
        chunk = ser.read(256)
        if chunk:
            buf += chunk

        while True:
            msg, buf = parse_packet(buf)
            if msg is None:
                break
            msg_type = get_u16(msg, 0)
            if msg_type == MSG_DEV_INFO:
                reply = bytearray(8)
                struct.pack_into('<H', reply, 0, MSG_BL_VER)
                struct.pack_into('<H', reply, 2, 4)
                ver = bl_version[:4].encode('ascii')
                reply[4:4+len(ver)] = ver
                pkt = make_packet(bytes(reply))
                ser.write(pkt)
                handshake_count += 1

    if handshake_count < 3:
        status("✗", C_ERR, "Handshake failed")
        ser.close()
        return False

    status("✓", C_OK, "Handshake complete")

    # ── phase 3: flash ──
    phase("Flashing firmware...")
    print()

    timestamp = int(time.time() * 100) & 0xFFFFFFFF
    t_start = time.time()

    for page in range(page_count):
        offset = page * 256
        chunk = fw_data[offset:offset+256]
        if len(chunk) < 256:
            chunk = chunk + b'\xff' * (256 - len(chunk))

        msg = bytearray(4 + 268)
        struct.pack_into('<H', msg, 0, MSG_PROG_FW)
        struct.pack_into('<H', msg, 2, 268)
        struct.pack_into('<I', msg, 4, timestamp)
        struct.pack_into('<H', msg, 8, page)
        struct.pack_into('<H', msg, 10, page_count)
        msg[16:16+256] = chunk

        pkt = make_packet(bytes(msg))
        ser.write(pkt)

        resp_deadline = time.time() + 5
        got_resp = False
        while time.time() < resp_deadline:
            rd = ser.read(256)
            if rd:
                buf += rd
            while True:
                rmsg, buf = parse_packet(buf)
                if rmsg is None:
                    break
                rtype = get_u16(rmsg, 0)
                if rtype == MSG_PROG_RESP:
                    err = get_u16(rmsg, 10) if len(rmsg) >= 12 else 0
                    if err != 0:
                        print()
                        status("✗", C_ERR, f"Flash error on page {page+1}: code {err}")
                        ser.close()
                        return False
                    got_resp = True
                    break
            if got_resp:
                break

        if not got_resp:
            print()
            status("✗", C_ERR, f"No response for page {page+1}/{page_count}")
            ser.close()
            return False

        progress_bar(page, page_count, t_start)

    elapsed = time.time() - t_start

    print(f"\n")
    status("✓", C_OK, f"Flash complete in {elapsed:.1f}s")
    print(f"\n  {C_OK}{BOLD}✦ Done. Radio will reboot.{RST}\n")
    ser.close()
    return True

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(LOGO)
        print(f"  {C_WHITE}Usage: {C_ACCENT}{sys.argv[0]} {C_CYAN}<port> <firmware.bin>{RST}")
        print(f"  {C_DIM}Example: k5flash.py /dev/ttyUSB0 firmware.bin{RST}\n")
        sys.exit(1)

    import os
    fw = sys.argv[2]
    if not os.path.isfile(fw):
        print(LOGO)
        status("✗", C_ERR, f"File not found: {C_ACCENT}{fw}")
        sys.exit(1)

    try:
        ok = flash(sys.argv[1], fw)
    except serial.SerialException as e:
        print(LOGO)
        status("✗", C_ERR, f"Serial error: {e}")
        ok = False
    except KeyboardInterrupt:
        print(f"\n\n  {C_WARN}▸ Interrupted{RST}\n")
        ok = False
    except Exception as e:
        print(f"\n  {C_ERR}✗{RST} {C_WHITE}{type(e).__name__}: {e}{RST}\n")
        ok = False
    sys.exit(0 if ok else 1)
