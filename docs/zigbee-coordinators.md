# Zigbee coordinator & USB router hardware

Per-site Zigbee radio hardware, the firmware each stick must run, and the
remote flash/recovery procedure. Written after the 2026-08 Monarto RX-desense
incident (see *History* below).

## Site hardware

| Site | Role | Hardware | Firmware | Where |
|------|------|----------|----------|-------|
| welland | Coordinator | Sonoff ZBDongle-E (Silabs EFR32MG21, `usb-ITEAD_SONOFF_Zigbee_3.0_USB_Dongle_Plus_V2`) | EmberZNet 7.4.5 | on the welland Z2M host |
| monarto | Coordinator | CC2652P stick, CH340 serial (`usb-1a86_USB_Serial`), **launchpad-pinout board** | Koenkk Z-Stack `CC1352P2_CC2652P_launchpad_coordinator_20250321` | ten64.monarto USB (bus 1 port 2), passed through to the `homeassistant` QEMU VM |
| monarto | Standalone router | `USB-Zigbee-Router` — TI CC2652 stick, IEEE `0x00124b0030e1c0ac`, Koenkk `ti.router` build 20250403 (variant unverified) | Koenkk Z-Stack router | outdoors, "Outside Purple Room behind BBQ", USB-charger powered |

Both networks share IEEE `0x00124b001cccafc1`, PAN `0x189e`, channel 11 —
monarto's network was restored from a coordinator backup that traces back to
welland's original TI stick. The sites are far apart, so the duplicate
identity is harmless.

## The variant rule (TI CC2652P sticks only)

Koenkk's `CC1352P2_CC2652P_*` builds come in two variants that differ ONLY in
which GPIOs drive the RF-frontend switch (and crystal trim):

- `launchpad`: RF-switch control on DIO 28/29 — TI LaunchPads, Sonoff
  ZBDongle-P, **and the monarto coordinator stick (empirically verified)**
- `other`: DIO 5/6 — E72-module DIY boards

**Flashing the wrong variant leaves the RF switch parked on the TX side: TX
works (even the 20 dBm high-PA path), but RX arrives through switch isolation
~25 dB down.** Symptoms: neighbors hear the stick fine, the stick's own
neighbor-table LQIs are 1–40, links wildly asymmetric (e.g. 95 one way, 7 the
other). Ember sticks (ZBDongle-E) have no variant concept — this trap is
TI-only.

Also: Z2M `advanced.transmit_power: 127` is NOT max on this stack — an
explicit `20` measured ~40 LQI higher at every neighbor. Both sites should
use `transmit_power: 20`.

## Remote reflash procedure (monarto coordinator)

No physical access needed; ~3 min Zigbee downtime. The recovery kit
(firmware hexes, `cc2538-bsl.py`, passthrough XML, coordinator backups, NV
tooling) lives in **`/home/tim/local/zigbee/`** on ten64.monarto. The
passthrough XML, for reference:

```xml
<hostdev mode='subsystem' type='usb' managed='yes'>
  <source>
    <vendor id='0x1a86'/>
    <product id='0x7523'/>
  </source>
</hostdev>
```

From ten64.monarto, in `/home/tim/local/zigbee/`:

```sh
# 1. Detach the stick from the HA VM (Z2M will crash-loop; see step 4)
sudo virsh detach-device homeassistant usb-zigbee-passthrough.xml --live

# 2. Flash (plain DTR/RTS bootloader entry works; --bootloader-sonoff-usb does NOT)
sudo chmod 666 /dev/ttyUSB0
uv run --with pyserial --with intelhex cc2538-bsl.py -p /dev/ttyUSB0 -evw \
  CC1352P2_CC2652P_launchpad_coordinator_<date>.hex

# 3. Reattach
sudo virsh attach-device homeassistant usb-zigbee-passthrough.xml --live

# 4. The Z2M addon watchdog gives up during the detach window — restart it:
sudo virsh qemu-agent-command homeassistant \
  '{"execute":"guest-exec","arguments":{"path":"/usr/bin/ha","arg":["addons","restart","45df7312_zigbee2mqtt"],"capture-output":true}}'
```

`-e` erases NV; Z2M restores the network from
`/config/zigbee2mqtt/coordinator_backup.json` automatically on start. Verify
with a `zigbee topology --format text` scan: coordinator neighbor-table LQIs
should be ~90–175, symmetric with the reverse direction.

The CCFG serial-bootloader backdoor (DIO15, active-low) is enabled in both
variants, so a bad flash is always serially recoverable.

## History

- 2026-03-16: monarto migrated from an Ember TCP bridge
  (`bridge-zigbee-1`, decommissioned) to the CC2652P stick — flashed with the
  **`other`** variant (hex kept in `/home/tim/local/zigbee/`, do not reuse).
- 2026-03..08: coordinator RX crippled (neighbor LQI median 4, e.g. heard
  Z10 at 7 while Z10 heard it at 95); worked well enough to go unnoticed
  until LQI landed in the `zigbee topology` tree output.
- 2026-08-05: reflashed to `launchpad` + `transmit_power: 20`. Coordinator RX
  median 4 → 33-and-climbing, fresh links 89–173, asymmetry gone. Before/after
  is preserved in monarto's discovery.db zigbee delta history.
- Outstanding: `USB-Zigbee-Router` still shows the same deaf-RX signature
  (RX median ~25) — suspect the same wrong-variant mistake. Fix: plug it into
  any computer and flash `CC1352P2_CC2652P_launchpad_router_20250403.zip`
  (same bootloader-entry notes as above; it re-pairs automatically keeping
  its IEEE).
