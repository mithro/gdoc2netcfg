# NSDP (Netgear Switch Discovery Protocol) Specification

## Overview

NSDP is a proprietary UDP broadcast protocol used by Netgear for discovering and
managing ProSAFE and Plus series switches. It uses a simple Type-Length-Value (TLV)
message format.

## Transport

| Parameter       | Value              |
|-----------------|--------------------|
| Protocol        | UDP (stateless)    |
| Client port     | 63321 (v2), 63323 (v1) |
| Server port     | 63322 (v2), 63324 (v1) |
| Discovery       | Broadcast to 255.255.255.255 |
| Byte order      | Big-endian (network byte order) |

## Packet Structure

### Header (32 bytes)

| Offset | Size | Field            | Description |
|--------|------|------------------|-------------|
| 0x00   | 1    | version          | Always 0x01 |
| 0x01   | 1    | operation        | See Operation Codes |
| 0x02   | 2    | result           | 0x0000=success, 0x0700=bad password |
| 0x04   | 4    | reserved_1       | Zeroed |
| 0x08   | 6    | client_mac       | Sender (manager) MAC address |
| 0x0E   | 6    | server_mac       | Target device MAC (00:00:00:00:00:00 = broadcast) |
| 0x14   | 2    | reserved_2       | Zeroed |
| 0x16   | 2    | sequence         | Incrementing per request |
| 0x18   | 4    | signature        | ASCII "NSDP" (0x4E534450) |
| 0x1C   | 4    | reserved_3       | Zeroed |

### Operation Codes

| Value | Name           |
|-------|----------------|
| 0x01  | Read Request   |
| 0x02  | Read Response  |
| 0x03  | Write Request  |
| 0x04  | Write Response |

### TLV Entry (4-byte header + variable data)

| Offset | Size | Field  | Description |
|--------|------|--------|-------------|
| 0x00   | 2    | tag    | Property identifier (big-endian uint16) |
| 0x02   | 2    | length | Length of value in bytes (big-endian uint16) |
| 0x04   | N    | value  | Property data (N = length bytes) |

For **read requests**, TLV entries have length=0 (request the property).
For **read responses** and **write requests**, TLV entries include data.

### End Marker

Every packet ends with tag=0xFFFF, length=0x0000 (4 bytes: FF FF 00 00).

## TLV Tag Registry

### Device Identity

| Tag      | Name             | Type    | R/W | Description |
|----------|------------------|---------|-----|-------------|
| 0x0001   | model            | string  | R   | Device model (e.g. "GS110EMX") |
| 0x0003   | hostname         | string  | R/W | Device name / hostname |
| 0x0004   | mac              | 6 bytes | R   | Device MAC address |
| 0x0005   | location         | string  | R/W | System location |
| 0x0006   | ip_address       | 4 bytes | R/W | Management IPv4 address |
| 0x0007   | netmask          | 4 bytes | R/W | IPv4 subnet mask |
| 0x0008   | gateway          | 4 bytes | R/W | Default gateway IPv4 |
| 0x000B   | dhcp_mode        | 1 byte  | R/W | 0=disabled, 1=enabled |
| 0x000D   | firmware_ver_1   | string  | R   | Firmware version (slot 1) |
| 0x000E   | firmware_ver_2   | string  | R   | Firmware version (slot 2) |
| 0x6000   | port_count       | 1 byte  | R   | Number of ports |
| 0x7800   | serial_number    | 1 byte + string | R | Device serial number: one prefix byte `0x01`, then the ASCII serial (observed on GS110EMX) |

### Port Information

| Tag      | Name             | Type    | R/W | Description |
|----------|------------------|---------|-----|-------------|
| 0x0C00   | port_status      | 3 bytes | R   | Per-port link status (repeated per port) |
| 0x1000   | port_statistics  | 49 bytes| R   | Per-port traffic stats (repeated per port) |

#### Port Status Encoding (3 bytes)

| Byte | Field       | Values |
|------|-------------|--------|
| 0    | port_id     | 1-based port number |
| 1    | link_speed  | 0x00=down, 0x01=10M-half, 0x02=10M-full, 0x03=100M-half, 0x04=100M-full, 0x05=1G |
| 2    | unknown     | Usually 0x01 |

**Note:** Speed values for 2.5G, 5G, and 10G are undocumented. The GS110EMX has
10G ports — actual values need to be discovered via packet capture on real hardware.

#### Port Statistics Encoding (49 bytes)

| Offset | Size | Field           |
|--------|------|-----------------|
| 0      | 1    | port_id         |
| 1-8    | 8    | bytes_received  |
| 9-16   | 8    | bytes_sent      |
| 17-24  | 8    | crc_errors      |
| 25-48  | 24   | unknown (6x uint64) |

### VLAN Configuration

| Tag      | Name             | Type    | R/W | Description |
|----------|------------------|---------|-----|-------------|
| 0x2000   | vlan_engine      | 1 byte  | R/W | 0=off, 1=basic-port, 2=adv-port, 3=basic-802.1Q, 4=adv-802.1Q |
| 0x2800   | vlan_members     | 4+ bytes| R   | VLAN membership (vlanId(2) + member bitfield + tagged bitfield) |
| 0x3000   | port_pvid        | 3 bytes | R   | Port PVID (portId(1) + vlanId(2)) |

### Authentication

| Tag      | Name             | Type    | Description |
|----------|------------------|---------|-------------|
| 0x000A   | password         | variable| XOR-encoded with key "NtgrSmartSwitchRock" |
| 0x0017   | auth_v2_salt     | variable| Auth v2 password salt (newer firmware) |
| 0x001A   | auth_v2_password | variable| Auth v2 password (newer firmware) |

### Other

| Tag      | Name               | Type    | R/W | Description |
|----------|--------------------|---------|-----|-------------|
| 0x0013   | reboot             | empty   | W   | Trigger device reboot |
| 0x0400   | factory_reset      | empty   | W   | Factory reset |
| 0x0000   | start_of_mark      | empty   | -   | Packet start marker |
| 0xFFFF   | end_of_mark        | empty   | -   | Packet end marker |

## Password Encoding

Passwords are XOR-encoded with the repeating key `NtgrSmartSwitchRock` (19 bytes).

## References

- [CursedHardware/go-nsdp protocol-design.md](https://github.com/CursedHardware/go-nsdp/blob/master/docs/protocol-design.md)
- [kamiraux/wireshark-nsdp NSDP_info](https://github.com/kamiraux/wireshark-nsdp/blob/master/NSDP_info)
- [AlbanBedel/libnsdp](https://github.com/AlbanBedel/libnsdp)
- [hdecarne-github/go-nsdp](https://github.com/hdecarne-github/go-nsdp)
