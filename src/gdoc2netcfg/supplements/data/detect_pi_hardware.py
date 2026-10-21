#!/usr/bin/env python3
"""What is this Raspberry Pi wearing, what powers it, what FPGA is on it?

Runs *on* the Pi (python3 >= 3.5 stdlib, needs sudo and i2c-tools) and prints
one line per finding plus verdicts. Copy it over and run it:

    scp tools/detect_pi_hardware.py pi@host:/tmp/ && ssh pi@host python3 /tmp/detect_pi_hardware.py
    ... --json          # machine-readable, for the audit and the sheet
    ... --jtag          # also drive the GPIO JTAG harness for an idcode and DNA

The same file is carried, unchanged, as roles/hw_identity/files/ in
welland-ansible-rpi and as the probe gdoc2netcfg's rpi-hardware scan ships
to each host; edit it here and copy it there.

FPGA boards, from what the Pi can see without touching the FPGA:
    PCIe: a NeTV2 running LitePCIe is 10ee:7024 with one 1 MiB BAR; an SQRL
    Acorn CLE-215+ is 1e24:021f (or 10ee:7011 under other gateware) with a
    128 KiB plus 64 KiB BAR pair. Config space and BAR *sizes* are read from
    sysfs, which the host bridge answers; a BAR is never mapped, because that
    wedged a host (rpi-hdcp-output inventory, section 1.3).
    USB: a Digilent Arty carries its own FT2232 (0403:6010, manufacturer
    "Digilent") whose serial (210319...) is the board's identity, and its
    host wears a Digilent Pmod HAT Adaptor with an ID EEPROM. A NeTV2 has no
    FTDI of its own; its JTAG is bit-banged from the host's GPIO.
    --jtag: run openFPGALoader over the GPIO harness (libgpiod, pins
    27:22:4:17) for the idcode and, on a 7-series, the Device DNA. Off by
    default because it drives four GPIO pins.

The fleet is powered by a mix of Waveshare PoE HATs and external PoE
splitters into micro-USB or USB-C, and no single signal separates them; this
collects every one that does discriminate, established on 2026-09-09:

HAT ID EEPROM at 0x50 on the ID bus (GPIO0/1)
    The firmware reads it and publishes /proc/device-tree/hat. The official
    Raspberry Pi PoE/PoE+ HATs and the Digilent Pmod HAT Adaptor have one.
HAT ID EEPROM at another address (0x51-0x57)
    Waveshare's PoE M.2 HAT+ (B) carries a well-formed HAT EEPROM at 0x52,
    which the firmware never reads, so the HAT is invisible in device-tree
    yet fully identifiable: product "Waveshare PoE M.2 HAT+ (B)", pid
    0x6d87. (Its vendor string is the literal placeholder "vendor " and
    every unit shares one UUID, so it names the model, not the unit.)
I2C devices on bus 1
    Waveshare PoE HAT (B) for 3B+/4B has an SSD1306 OLED at 0x3c and a
    PCF8574 fan controller at 0x20. Nothing else in the line-up puts
    anything on bus 1.
USB tree
    Waveshare's PoE-ETH-USB-HUB-HAT for a Pi Zero is a Terminus 1a40:0101
    hub on the root port with an RTL8152 (0bda:8152) on its port 4.
Pi 5 firmware power fields
    /proc/device-tree/chosen/power/max_current is the firmware's verdict on
    the USB-C source: 5000 after a PD contract, 3000 when there is no PD
    contract *including when nothing is on USB-C at all* (a HAT feeding the
    GPIO 5 V pins), 1500 or 900 when a resistor-only USB-C source advertises
    that much. So 900 or 1500 proves an external USB-C supply, i.e. a
    splitter; 3000 is a GPIO HAT or a 3 A splitter and needs another signal.
Pi 5 PMIC ADC (vcgencmd pmic_read_adc)
    EXT5V_V is the 5 V input as the PMIC sees it: the GPIO-fed HATs in this
    fleet sit at 5.1-5.4 V, the splitter-fed boards at 4.8-5.0 V. BATT_V is
    the RTC backup cell: about 3 V when one is fitted, near 0 V when not.
Pi 5 fan header
    /proc/device-tree/cooling_fan/status is "okay" only when the firmware
    found a fan on the header; the pwmfan hwmon then gives its speed. A fan
    here is the Pi's own (the official Active Cooler or similar): Waveshare's
    PoE M.2 HAT+ (B) ships without one and is built to fit over the Active
    Cooler, and the PoE HAT (F)'s fan is on the HAT, powered by the HAT.
Switch side (not read here): the 802.3af class the PD announces
    Waveshare PoE-ETH-USB-HUB-HAT: class 3. Waveshare PoE M.2 HAT+ (B): 4.
    802.3af-only HATs (B, D, E) cannot be class 4. See detect_poe_class.py.

What still cannot be told apart from the Pi: an EEPROM-less GPIO HAT on a
Pi 5 (Waveshare F, G, H, J) from a 3 A USB-C splitter, and on a 3B+/4 an
EEPROM-less, I2C-less HAT (Waveshare C, D, E) from any splitter -- and the
(C) *is* a splitter electrically, feeding the Pi's USB power input from a
USB-A socket. Those need the switch class or a look at the board.
"""
import glob
import json
import os
import re
import struct
import subprocess
import sys
import uuid


def sh(args, timeout=15):
    """Run a fixed argument list (never a shell) and return its stdout."""
    try:
        r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=timeout)   # 3.5-safe
        return r.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        return ""


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read().rstrip(b"\0").decode("ascii", "replace").strip()
    except OSError:
        return None


def dt_u32(path):
    try:
        with open(path, "rb") as f:
            return struct.unpack(">I", f.read(4))[0]
    except (OSError, struct.error):
        return None


# --- HAT EEPROM -------------------------------------------------------------

def eeprom_read(bus, addr, length=256):
    out = b""
    for off in range(0, length, 128):
        r = sh(["sudo", "i2ctransfer", "-y", str(bus), "w2@0x%02x" % addr,
                "0x%02x" % (off >> 8), "0x%02x" % (off & 0xff), "r128"])
        if not r or "Error" in r:
            return None
        out += bytes(int(x, 16) for x in r.split())
    return out


def eeprom_decode(blob):
    if not blob or blob[:4] != b"R-Pi":
        return None
    ver, _, numatoms, eeplen = struct.unpack_from("<BBHI", blob, 4)
    pos, info = 12, {"version": ver, "atoms": []}
    for _ in range(numatoms):
        if pos + 8 > len(blob):
            break
        atype, count, dlen = struct.unpack_from("<HHI", blob, pos)
        data = blob[pos + 8:pos + 8 + dlen - 2]
        if atype == 1 and len(data) >= 22:
            pid, pver, vslen, pslen = struct.unpack_from("<HHBB", data, 16)
            info.update(uuid=str(uuid.UUID(bytes_le=data[0:16])), pid="0x%04x" % pid,
                        pver="0x%04x" % pver,
                        vendor=data[22:22 + vslen].decode("ascii", "replace"),
                        product=data[22 + vslen:22 + vslen + pslen].decode("ascii", "replace"))
        elif atype == 3:
            info["dt_blob"] = data.decode("ascii", "replace")
        pos += 8 + dlen
    return info


def id_bus_scan():
    """Find HAT EEPROMs on the ID bus, enabling it at runtime if needed."""
    enabled_here = False
    if not os.path.exists("/dev/i2c-0"):
        sh(["sudo", "dtparam", "i2c_vc=on"])
        enabled_here = os.path.exists("/dev/i2c-0")
        if not enabled_here:
            return {}
    found = {}
    for addr in range(0x50, 0x58):
        info = eeprom_decode(eeprom_read(0, addr))
        if info:
            found["0x%02x" % addr] = info
    if enabled_here:
        sh(["sudo", "dtparam", "-r"])
    return found


# --- FPGA boards ---------------------------------------------------------------

def pcie_devices():
    """Every PCIe endpoint that is not a bridge, with its BAR sizes from
    sysfs `resource` (start end flags per line) -- never a mapping."""
    out = []
    for p in sorted(glob.glob("/sys/bus/pci/devices/*")):
        cls = read(p + "/class") or ""
        if cls.startswith("0x0604"):        # PCI-PCI bridge: the root port
            continue
        vend, dev = read(p + "/vendor"), read(p + "/device")
        bars = []
        for line in (read(p + "/resource") or "").splitlines():
            parts = line.split()
            if len(parts) == 3:
                start, end = int(parts[0], 16), int(parts[1], 16)
                if end > start:
                    bars.append(end - start + 1)
        out.append({"slot": os.path.basename(p), "id": "%s:%s" % (vend[2:], dev[2:]),
                    "class": cls, "bars": bars,
                    "subsystem": "%s:%s" % ((read(p + "/subsystem_vendor") or "0x????")[2:],
                                            (read(p + "/subsystem_device") or "0x????")[2:])})
    return out


def ftdi_devices():
    out = []
    for p in sorted(glob.glob("/sys/bus/usb/devices/*")):
        if read(p + "/idVendor") == "0403":
            out.append({"path": os.path.basename(p), "id": "0403:" + (read(p + "/idProduct") or ""),
                        "manufacturer": read(p + "/manufacturer"), "product": read(p + "/product"),
                        "serial": read(p + "/serial")})
    return out


def jtag_probe():
    """openFPGALoader over the host's GPIO harness. Returns None when the
    tool is missing, the idcode line when a chain answers."""
    if not sh(["which", "openFPGALoader"]):
        return {"error": "openFPGALoader not installed"}
    harness = ["sudo", "openFPGALoader", "-c", "libgpiod", "--pins=27:22:4:17"]
    det = sh(harness + ["--detect"], timeout=60)
    m = re.search(r"idcode\s+(0x[0-9a-f]+)", det)
    if not m:
        return {"idcode": None, "raw": det[-200:]}
    res = {"idcode": m.group(1)}
    fam = re.search(r"family\s+(.*?)\s*$", det, re.M)
    if fam:
        res["family"] = fam.group(1)
    dna = sh(harness + ["--read-dna"], timeout=60)
    m = re.search(r'"dna":\s*"(0x[0-9a-f]+)"', dna)
    res["dna"] = m.group(1) if m else None
    return res


def fpga_verdict(d):
    """Name the FPGA board(s) this Pi hosts, from PCIe, USB and JTAG."""
    boards = []
    for pc in d["pcie"]:
        sizes = sorted(pc["bars"], reverse=True)
        if pc["id"] == "10ee:7024" and sizes == [1 << 20]:
            boards.append({"kind": "netv2", "slot": pc["slot"],
                           "how": "PCIe 10ee:7024, one 1 MiB BAR (LitePCIe NeTV2 gateware)"})
        elif pc["id"] in ("1e24:021f", "10ee:7011") and sizes == [128 << 10, 64 << 10]:
            boards.append({"kind": "acorn", "slot": pc["slot"],
                           "how": "PCIe %s, 128 KiB + 64 KiB BARs (SQRL Acorn CLE-215+%s)" % (
                               pc["id"], "" if pc["id"] == "1e24:021f" else ", default Xilinx id")})
        elif pc["id"].startswith("10ee:") or pc["id"].startswith("1e24:"):
            boards.append({"kind": "unknown-fpga", "how": "PCIe %s, BARs %s" % (pc["id"], sizes),
                           "slot": pc["slot"]})
    for f in d["ftdi"]:
        if f["id"] == "0403:6010" and (f["manufacturer"] or "").startswith("Digilent"):
            boards.append({"kind": "arty", "how": "Digilent FT2232 %s" % f["serial"],
                           "serial": f["serial"]})
    j = d.get("jtag")
    if j and j.get("idcode"):
        entry = {"kind": "jtag", "how": "GPIO JTAG idcode %s%s" % (
            j["idcode"], (" " + j["family"]) if j.get("family") else ""), "idcode": j["idcode"],
            "dna": j.get("dna")}
        # A chain on the GPIO harness is how a NeTV2 is reached, and it is
        # the only board in this fleet driven that way, so a chain with no
        # Arty beside it is a NeTV2 whether or not its PCIe edge is cabled
        # (a Pi 5 always lists the RP1 as a PCIe endpoint, so "no PCIe" is
        # never a usable test). When PCIe already named the board, the
        # idcode and DNA join that entry. An Arty is on its own FTDI, never
        # the harness, so a chain beside an Arty stays "jtag".
        netv2 = [b for b in boards if b["kind"] == "netv2"]
        if netv2:
            netv2[0].update(idcode=j["idcode"], dna=j.get("dna"),
                            how=netv2[0]["how"] + "; " + entry["how"])
        else:
            if not any(b["kind"] == "arty" for b in boards):
                entry["kind"] = "netv2"
            boards.append(entry)
    return boards


# --- collect ------------------------------------------------------------------

def collect():
    d = {}
    d["model"] = read("/proc/device-tree/model") or ""
    d["serial"] = read("/proc/device-tree/serial-number")
    m = re.search(r"^Revision\s*:\s*(\S+)", read("/proc/cpuinfo") or "", re.M)
    d["revision"] = m.group(1) if m else None
    d["hat_fw"] = None
    if os.path.isdir("/proc/device-tree/hat"):
        d["hat_fw"] = {k: read("/proc/device-tree/hat/" + k)
                       for k in ("vendor", "product", "product_id", "product_ver", "uuid")}
    d["hat_eeproms"] = id_bus_scan()
    if os.path.exists("/dev/i2c-1"):
        r = sh(["sudo", "i2cdetect", "-y", "1"])
        d["i2c1"] = sorted(set(re.findall(r"\b([0-7][0-9a-f])\b", "\n".join(r.split("\n")[1:])))
                           - set("%02x" % x for x in range(0, 0x80, 0x10)))
    else:
        d["i2c1"] = None
    usb = {}
    for p in glob.glob("/sys/bus/usb/devices/*"):
        v, pr = read(p + "/idVendor"), read(p + "/idProduct")
        if v:
            usb[os.path.basename(p)] = "%s:%s" % (v, pr)
    d["usb"] = usb
    # What the power port itself reports. Every model: the firmware's
    # throttle flags, whose bit 0 is under-voltage now and bit 16
    # under-voltage since boot -- the only thing a 3B+, Zero or Pi 4 can say
    # about the supply on its micro-USB or USB-C. Pi 5: the firmware's USB-C
    # judgement, below.
    thr = sh(["vcgencmd", "get_throttled"])
    m = re.search(r"0x([0-9a-f]+)", thr)
    t = int(m.group(1), 16) if m else None
    d["throttled"] = ("0x%x" % t) if t is not None else None
    d["undervoltage_now"] = bool(t & 0x1) if t is not None else None
    d["undervoltage_since_boot"] = bool(t & 0x10000) if t is not None else None
    d["pcie"] = pcie_devices()
    d["ftdi"] = ftdi_devices()
    d["jtag"] = jtag_probe() if "--jtag" in sys.argv else None
    pi5 = "Pi 5" in d["model"]
    d["pi5"] = pi5
    if pi5:
        d["max_current_ma"] = dt_u32("/proc/device-tree/chosen/power/max_current")
        try:
            with open("/proc/device-tree/chosen/power/usbpd_power_data_objects", "rb") as f:
                raw = f.read()
            pdos = [struct.unpack_from(">I", raw, i)[0] for i in range(0, len(raw) - 3, 4)]
            d["usbpd_pdos"] = ["0x%08x" % x for x in pdos if x]
        except OSError:
            d["usbpd_pdos"] = None
        adc = sh(["sudo", "vcgencmd", "pmic_read_adc"])
        m = re.search(r"EXT5V_V volt\(\d+\)=([0-9.]+)V", adc)
        d["ext5v_v"] = float(m.group(1)) if m else None
        m = re.search(r"BATT_V volt\(\d+\)=([0-9.]+)V", adc)
        d["rtc_batt_v"] = float(m.group(1)) if m else None
        d["fan_dt"] = read("/proc/device-tree/cooling_fan/status")
        d["fan_rpm"] = None
        for h in glob.glob("/sys/class/hwmon/hwmon*"):
            if read(h + "/name") == "pwmfan":
                d["fan_rpm"] = int(read(h + "/fan1_input") or 0)
    return d


# --- verdict ------------------------------------------------------------------

def verdict(d):
    ev, header, power = [], [], None
    for addr, e in d["hat_eeproms"].items():
        header.append("%s (HAT EEPROM at %s, pid %s%s)" % (
            e.get("product", "?").strip(), addr, e.get("pid"),
            "" if addr == "0x50" else ", firmware does not read it"))
        if "PoE" in e.get("product", ""):
            power = "PoE HAT on the GPIO header: " + e["product"].strip()
    if d["hat_fw"]:
        fw_name = "%s %s" % (d["hat_fw"]["vendor"], d["hat_fw"]["product"])
        header.append(fw_name + " (firmware-read HAT EEPROM)")
        if "PoE" in (d["hat_fw"]["product"] or ""):
            power = "PoE HAT on the GPIO header: " + fw_name
    i2c1 = d.get("i2c1") or []
    if "3c" in i2c1 and "20" in i2c1:
        header.append("Waveshare PoE HAT (B) (SSD1306 at 0x3c + PCF8574 at 0x20 on bus 1)")
        power = "PoE HAT on the GPIO header: Waveshare PoE HAT (B)"
    elif i2c1:
        ev.append("bus 1 devices: " + " ".join(i2c1))
    usb = d["usb"]
    roots = [k for k, v in usb.items() if v == "1a40:0101" and k.count(".") == 0 and "-" in k]
    for r in roots:
        if usb.get(r + ".4") == "0bda:8152":
            header.append("Waveshare PoE-ETH-USB-HUB-HAT (1a40:0101 hub with RTL8152 on port 4)")
            power = "PoE through the Waveshare PoE-ETH-USB-HUB-HAT bonnet"
    if d["pi5"]:
        mc = d["max_current_ma"]
        ev.append("USB-C as the firmware sees it: max_current %s mA, %s; 5 V input %.2f V" % (
            mc,
            ("PD objects " + " ".join(d["usbpd_pdos"])) if d.get("usbpd_pdos")
            else "no PD contract",
            d["ext5v_v"] or 0))
        if mc in (900, 1500):
            power = power or ("external supply on USB-C advertising %d mA by resistor: "
                              "a PoE splitter or a USB-A lead" % mc)
        elif mc == 5000:
            power = power or "USB-C source with a PD contract: a PD supply or a PD splitter"
        elif mc == 3000 and not power:
            lean = ("5 V input above 5.1 V leans HAT" if (d["ext5v_v"] or 0) > 5.1
                    else "5 V input at or below 5.0 V leans splitter")
            power = ("ambiguous: no PD contract, so either a GPIO-fed HAT without an ID EEPROM "
                     "(Waveshare F/G/H/J) or a 3 A USB-C splitter; " + lean)
        ev.append("fan header: %s%s" % (d["fan_dt"] or "no node",
                  ", %d rpm" % d["fan_rpm"] if d["fan_rpm"] is not None else ""))
        batt = d["rtc_batt_v"] or 0
        ev.append("RTC battery: %s" % ("fitted, %.2f V" % batt if batt > 1.0
                                       else "none (%.2f V)" % batt))
    if d.get("throttled") is not None:
        ev.append("power port: throttled=%s%s%s" % (
            d["throttled"], ", under-voltage NOW" if d["undervoltage_now"] else "",
            ", under-voltage since boot" if d["undervoltage_since_boot"] else ""))
    if not power:
        power = ("nothing on the Pi distinguishes it: a HAT with no ID EEPROM and no I2C devices "
                 "(Waveshare C, D, E) or an external splitter; use the switch's PD class or look")
    fpga = fpga_verdict(d)
    return {"header": header or ["nothing identifiable on the header"], "power": power,
            "evidence": ev, "fpga": fpga, "summary": summary(d, header, power, fpga)}


def summary(d, header, power, fpga):
    """The verdict in a fixed shape for the audit and the ansible assert:
    short names only, and None where the signal does not exist on this
    model rather than a guess."""
    items = []
    for addr, e in d["hat_eeproms"].items():
        items.append(e.get("product", "?").strip())
    if d["hat_fw"] and (d["hat_fw"]["product"] or "").strip() not in items:
        items.append("%s %s" % (d["hat_fw"]["vendor"], d["hat_fw"]["product"]))
    for h in header:
        bonnet = "Waveshare PoE-ETH-USB-HUB-HAT"
        if h.startswith(bonnet) and bonnet not in items:
            items.append(bonnet)
        if h.startswith("Waveshare PoE HAT (B)") and "Waveshare PoE HAT (B)" not in items:
            items.append("Waveshare PoE HAT (B)")
    if power.startswith("PoE HAT on the GPIO header"):
        pclass = "gpio-poe-hat"
    elif power.startswith("PoE through the Waveshare PoE-ETH-USB-HUB-HAT"):
        pclass = "bonnet-poe"
    elif power.startswith("external supply on USB-C"):
        pclass = "usbc-supply"
    elif power.startswith("USB-C source with a PD contract"):
        pclass = "usbc-pd-supply"
    elif power.startswith("ambiguous"):
        pclass = "ambiguous"
    else:
        pclass = "undetermined"
    boards = []
    for b in fpga:
        entry = {"kind": b["kind"]}
        for k in ("serial", "dna", "idcode"):
            if b.get(k):
                entry[k] = b[k]
        boards.append(entry)
    return {
        "model": d["model"], "serial": d["serial"], "revision": d["revision"],
        "header": items, "power_class": pclass, "fpga": boards,
        "rtc_battery": ((d.get("rtc_batt_v") or 0) > 1.0) if d["pi5"] else None,
        "fan": (d.get("fan_dt") == "okay") if d["pi5"] else None,
        "max_current_ma": d.get("max_current_ma") if d["pi5"] else None,
        "ext5v_v": d.get("ext5v_v") if d["pi5"] else None,
    }


def main():
    d = collect()
    v = verdict(d)
    if "--json" in sys.argv:
        d["verdict"] = v
        print(json.dumps(d, indent=1))
        return
    print("%s  serial %s  rev %s" % (d["model"], d["serial"], d["revision"]))
    for h in v["header"]:
        print("  header : " + h)
    for e in v["evidence"]:
        print("  signal : " + e)
    print("  power  : " + v["power"])
    for b in v["fpga"]:
        print("  fpga   : %s (%s)%s" % (b["kind"], b["how"],
                                        (", DNA " + b["dna"]) if b.get("dna") else ""))


if __name__ == "__main__":
    main()
