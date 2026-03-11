"""Host models: network interfaces, hosts, and the full inventory."""

from __future__ import annotations

from dataclasses import dataclass, field

from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.models.switch_data import SwitchData


@dataclass(frozen=True)
class DNSName:
    """A DNS name with its associated IP addresses.

    Each DNS name maps to zero or more IP addresses. The is_fqdn flag
    distinguishes full domain names (e.g. 'big-storage.welland.mithis.com')
    from short names (e.g. 'big-storage').
    """

    name: str
    ip_addresses: tuple[IPv4Address | IPv6Address, ...] = ()
    is_fqdn: bool = False

    @property
    def ipv4(self) -> IPv4Address | None:
        """The first IPv4 address for this name, or None."""
        for ip in self.ip_addresses:
            if isinstance(ip, IPv4Address):
                return ip
        return None

    @property
    def ipv4_addresses(self) -> tuple[IPv4Address, ...]:
        """All IPv4 addresses for this name."""
        return tuple(ip for ip in self.ip_addresses if isinstance(ip, IPv4Address))

    @property
    def ipv6_addresses(self) -> tuple[IPv6Address, ...]:
        """All IPv6 addresses for this name."""
        return tuple(ip for ip in self.ip_addresses if isinstance(ip, IPv6Address))


@dataclass(frozen=True)
class NetworkInterface:
    """A single network interface on a host.

    Attributes:
        name: Interface name (e.g. 'eth0', 'bmc'), or None for the default/only interface
        mac: Ethernet MAC address
        ip_addresses: All IP addresses (IPv4 and IPv6) for this interface
        vlan_id: VLAN this interface belongs to (derived from IP)
        dhcp_name: Name used for DHCP registration
    """

    name: str | None
    mac: MACAddress
    ip_addresses: tuple[IPv4Address | IPv6Address, ...] = ()
    vlan_id: int | None = None
    dhcp_name: str = ""

    @property
    def ipv4(self) -> IPv4Address:
        """The IPv4 address for this interface (first IPv4 in ip_addresses)."""
        for ip in self.ip_addresses:
            if isinstance(ip, IPv4Address):
                return ip
        raise ValueError("NetworkInterface has no IPv4 address")

    @property
    def ipv6_addresses(self) -> tuple[IPv6Address, ...]:
        """All IPv6 addresses for this interface."""
        return tuple(ip for ip in self.ip_addresses if isinstance(ip, IPv6Address))


@dataclass(frozen=True)
class VirtualInterface:
    """A logical network endpoint grouping physical NICs that share an IP.

    When a device has multiple physical interfaces (e.g. wired + wireless)
    with the same IPv4, they are grouped into one VirtualInterface.
    Single-NIC endpoints produce a VirtualInterface with one MAC.

    Attributes:
        name: Interface name from the first physical NIC (None for default).
        ip_addresses: All IP addresses (IPv4 and IPv6) for this endpoint.
        macs: All MAC addresses for this IP (tuple for immutability).
        dhcp_names: DHCP names from all physical NICs (tuple for immutability).
        vlan_id: VLAN ID (from the first physical NIC).
    """

    name: str | None
    ip_addresses: tuple[IPv4Address | IPv6Address, ...]
    macs: tuple[MACAddress, ...]
    dhcp_names: tuple[str, ...] = ()
    vlan_id: int | None = None

    @property
    def ipv4(self) -> IPv4Address:
        """The shared IPv4 address."""
        for ip in self.ip_addresses:
            if isinstance(ip, IPv4Address):
                return ip
        raise ValueError("VirtualInterface has no IPv4 address")

    @property
    def ipv6_addresses(self) -> tuple[IPv6Address, ...]:
        """IPv6 addresses for this endpoint."""
        return tuple(ip for ip in self.ip_addresses if isinstance(ip, IPv6Address))

    @property
    def all_ips(self) -> tuple[str, ...]:
        """All IP addresses (v4 and v6) as strings."""
        return tuple(str(a) for a in self.ip_addresses)


@dataclass(frozen=True)
class SSLCertInfo:
    """SSL/TLS certificate information for a host.

    Populated by the ssl_certs supplement after scanning port 443.
    """

    issuer: str
    self_signed: bool
    valid: bool
    expiry: str
    sans: tuple[str, ...] = ()


@dataclass(frozen=True)
class SNMPData:
    """SNMP data collected from a host.

    Populated by the snmp supplement after querying SNMP agents.
    All fields use immutable types (tuples of tuples) to match the
    frozen dataclass guarantee.

    Attributes:
        snmp_version: Protocol version used ("v1", "v2c", or "v3").
        system_info: System group key-value pairs (sysDescr, sysName, etc.).
        interfaces: ifTable rows, each row as key-value pairs.
        ip_addresses: ipAddrTable rows, each row as key-value pairs.
        raw: All collected OID→value pairs for extensibility.
    """

    snmp_version: str
    system_info: tuple[tuple[str, str], ...] = ()
    interfaces: tuple[tuple[tuple[str, str], ...], ...] = ()
    ip_addresses: tuple[tuple[tuple[str, str], ...], ...] = ()
    raw: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class BMCFirmwareInfo:
    """BMC firmware information from ipmitool mc info.

    Populated by the bmc_firmware supplement after probing Supermicro BMCs.

    Attributes:
        product_name: Board model from ipmitool (e.g. "X11SPM-T(P)F").
        firmware_revision: BMC firmware version (e.g. "1.74").
        ipmi_version: IPMI protocol version (e.g. "2.0").
        series: Supermicro series number extracted from product_name
            (e.g. 11 for X11, 9 for X9), or None if not parseable.
        snmp_capable: Whether this BMC series supports SNMP.
            True for X10+ (AST2400/2500/2600), False for X9 and earlier
            (ATEN WPCM450).
    """

    product_name: str
    firmware_revision: str
    ipmi_version: str
    series: int | None
    snmp_capable: bool


@dataclass(frozen=True)
class BridgeData:
    """Switch bridge/topology data collected via SNMP.

    Populated by the bridge supplement for managed switches.
    Contains MAC address table, VLAN configuration, LLDP neighbors,
    and port status. All fields use immutable types.

    Attributes:
        mac_table: (mac_str, vlan_id, bridge_port, port_name) tuples.
        vlan_names: (vlan_id, name) tuples from dot1qVlanStaticName.
        port_pvids: (ifIndex, pvid) tuples from dot1qPvid.
        port_names: (ifIndex, name) tuples from ifName.
        port_status: (ifIndex, oper_status, speed_mbps) tuples.
        lldp_neighbors: (local_ifIndex, remote_sysname, remote_port_id,
            remote_chassis_mac) tuples.
        vlan_egress_ports: (vlan_id, port_bitmap_hex) tuples for tagged membership.
        vlan_untagged_ports: (vlan_id, port_bitmap_hex) tuples for untagged membership.
        poe_status: (ifIndex, admin_status, detection_status) tuples.
        port_statistics: (ifIndex, bytes_rx, bytes_tx, errors) tuples
            from ifHCInOctets, ifHCOutOctets, ifInErrors.
    """

    mac_table: tuple[tuple[str, int, int, str], ...] = ()
    vlan_names: tuple[tuple[int, str], ...] = ()
    port_pvids: tuple[tuple[int, int], ...] = ()
    port_names: tuple[tuple[int, str], ...] = ()
    port_status: tuple[tuple[int, int, int], ...] = ()
    lldp_neighbors: tuple[tuple[int, str, str, str], ...] = ()
    vlan_egress_ports: tuple[tuple[int, str], ...] = ()
    vlan_untagged_ports: tuple[tuple[int, str], ...] = ()
    poe_status: tuple[tuple[int, int, int], ...] = ()
    port_statistics: tuple[tuple[int, int, int, int], ...] = ()


@dataclass(frozen=True)
class NSDPData:
    """NSDP discovery data for a Netgear switch.

    Populated by the nsdp supplement after broadcast discovery.
    Contains device identity, port status, and VLAN configuration
    as reported by the Netgear Switch Discovery Protocol.

    Attributes:
        model: Device model string (e.g. "GS110EMX").
        mac: Device MAC address as colon-separated hex string.
        hostname: Device name.
        ip: Management IPv4 address.
        netmask: IPv4 subnet mask.
        gateway: Default gateway IPv4.
        firmware_version: Firmware version string.
        dhcp_enabled: Whether DHCP is enabled.
        port_count: Number of ports.
        serial_number: Device serial number.
        port_status: Per-port link status as (port_id, speed_byte) tuples.
        port_pvids: Per-port native VLAN as (port_id, vlan_id) tuples.
    """

    model: str
    mac: str
    hostname: str | None = None
    ip: str | None = None
    netmask: str | None = None
    gateway: str | None = None
    firmware_version: str | None = None
    dhcp_enabled: bool | None = None
    port_count: int | None = None
    serial_number: str | None = None
    port_status: tuple[tuple[int, int], ...] = ()
    port_pvids: tuple[tuple[int, int], ...] = ()
    vlan_engine: int | None = None  # 0=disabled, 4=advanced 802.1Q
    vlan_members: tuple[tuple[int, frozenset[int], frozenset[int]], ...] = ()
    # Each tuple: (vlan_id, member_ports, tagged_ports)
    port_statistics: tuple[tuple[int, int, int, int], ...] = ()
    # Each tuple: (port_id, bytes_rx, bytes_tx, crc_errors)
    qos_engine: int | None = None  # 0=disabled, 1=port-based, 2=802.1p
    port_mirroring_dest: int | None = None  # Destination port (0=disabled)
    igmp_snooping_enabled: bool | None = None
    broadcast_filtering: bool | None = None
    loop_detection: bool | None = None


@dataclass(frozen=True)
class TasmotaData:
    """Tasmota device status data collected via HTTP API.

    Populated by the tasmota supplement after querying Status 0.
    Contains device identity, MQTT configuration, WiFi status,
    and operational state.

    Attributes:
        device_name: Configured device name (DeviceName).
        friendly_name: Display name for relays (FriendlyName1).
        hostname: mDNS/network hostname.
        firmware_version: Tasmota firmware version string.
        mqtt_host: MQTT broker hostname.
        mqtt_port: MQTT broker port.
        mqtt_topic: MQTT topic for this device.
        mqtt_client: MQTT client ID.
        mac: Device MAC address as colon-separated hex.
        ip: Device IPv4 address.
        wifi_ssid: Connected WiFi SSID.
        wifi_rssi: WiFi RSSI percentage (0-100).
        wifi_signal: WiFi signal strength in dBm.
        uptime: Device uptime string (e.g. "3T12:34:56").
        module: Hardware module type string.
        controls: Hostnames this device controls, parsed from spreadsheet.
    """

    device_name: str
    friendly_name: str
    hostname: str
    firmware_version: str
    mqtt_host: str
    mqtt_port: int
    mqtt_topic: str
    mqtt_client: str
    mac: str
    ip: str
    wifi_ssid: str = ""
    wifi_rssi: int = 0
    wifi_signal: int = 0
    uptime: str = ""
    module: str = ""
    controls: tuple[str, ...] = ()


@dataclass
class Host:
    """A logical host with one or more network interfaces.

    Built by aggregating raw device records that share the same machine name.
    All hosts are treated as multi-homed: bare hostnames resolve to ALL
    interface IPs via round-robin DNS.

    Attributes:
        machine_name: Raw machine name from the spreadsheet
        hostname: Computed hostname (may include suffix like '.iot')
        sheet_type: Which spreadsheet sheet this came from ('Network', 'IoT', etc.)
        interfaces: All network interfaces for this host
        sshfp_records: SSH fingerprint records (derived from ssh_host_keys)
        ssh_host_keys: Raw SSH public key lines ("hostname key-type base64-key")
        extra: Additional spreadsheet columns preserved for generators
    """

    machine_name: str
    hostname: str
    sheet_type: str = "Network"
    interfaces: list[NetworkInterface] = field(default_factory=list)
    sshfp_records: list[str] = field(default_factory=list)
    ssh_host_keys: list[str] = field(default_factory=list)
    extra: dict[str, str] = field(default_factory=dict)
    alt_names: list[str] = field(default_factory=list)
    dns_names: list[DNSName] = field(default_factory=list)
    hardware_type: str | None = None
    ssl_cert_info: SSLCertInfo | None = None
    snmp_data: SNMPData | None = None
    bmc_firmware_info: BMCFirmwareInfo | None = None
    bridge_data: BridgeData | None = None
    nsdp_data: NSDPData | None = None
    switch_data: SwitchData | None = None
    tasmota_data: TasmotaData | None = None

    @property
    def first_ipv4(self) -> IPv4Address | None:
        """First interface's IPv4 address, or None if no interfaces.

        Convenience for consumers that need a single IP to talk to
        (e.g. SNMP probe, Nagios check). Not semantically a "default" —
        just the first in interface order.
        """
        if self.interfaces:
            return self.interfaces[0].ipv4
        return None

    @property
    def interface_by_name(self) -> dict[str | None, NetworkInterface]:
        """Map interface names to interfaces."""
        return {iface.name: iface for iface in self.interfaces}

    @property
    def all_ipv4(self) -> dict[str | None, IPv4Address]:
        """Map interface names to their IPv4 addresses."""
        return {iface.name: iface.ipv4 for iface in self.interfaces}

    @property
    def all_macs(self) -> list[MACAddress]:
        """All MAC addresses across all interfaces."""
        return [iface.mac for iface in self.interfaces]

    def is_bmc(self) -> bool:
        """Check if any interface is a BMC (Baseboard Management Controller)."""
        return any(
            iface.name and 'bmc' in iface.name.lower()
            for iface in self.interfaces
        )

    @property
    def virtual_interfaces(self) -> list[VirtualInterface]:
        """Group physical interfaces by IPv4 into logical endpoints.

        Interfaces sharing the same IPv4 (e.g. wired + wireless on the
        same device) are combined into one VirtualInterface with multiple
        MACs.  Order follows first occurrence in self.interfaces.
        """
        groups: dict[str, list[NetworkInterface]] = {}
        for iface in self.interfaces:
            key = str(iface.ipv4)
            groups.setdefault(key, []).append(iface)
        result = []
        for ifaces in groups.values():
            first = ifaces[0]
            # Combine IPv4 + IPv6 into unified ip_addresses
            ip_addrs: list[IPv4Address | IPv6Address] = [first.ipv4]
            ip_addrs.extend(first.ipv6_addresses)
            result.append(VirtualInterface(
                name=first.name,
                ip_addresses=tuple(ip_addrs),
                macs=tuple(i.mac for i in ifaces),
                dhcp_names=tuple(i.dhcp_name for i in ifaces),
                vlan_id=first.vlan_id,
            ))
        return result

    def is_multi_interface(self) -> bool:
        """Check if this host has multiple distinct IP endpoints."""
        return len(self.virtual_interfaces) > 1


@dataclass
class NetworkInventory:
    """The fully enriched network data model.

    This is the output of the pipeline's derivation and supplement stages,
    and the input to all generators. Contains the site configuration, all
    hosts, and precomputed indexes for efficient lookup.

    Attributes:
        site: Site topology configuration
        hosts: All hosts in the inventory
        ip_to_hostname: Precomputed IP→hostname mapping
        ip_to_macs: Precomputed IP→[(mac, dhcp_name)] mapping
    """

    site: Site
    hosts: list[Host] = field(default_factory=list)
    ip_to_hostname: dict[str, str] = field(default_factory=dict)
    ip_to_macs: dict[str, list[tuple[MACAddress, str]]] = field(default_factory=dict)

    def hosts_sorted(self) -> list[Host]:
        """Return hosts sorted by reversed hostname components.

        This matches the existing dnsmasq.py sort order for host-record output.
        """
        return sorted(self.hosts, key=lambda h: h.hostname.split('.')[::-1])

    def host_by_hostname(self, hostname: str) -> Host | None:
        """Look up a host by its hostname."""
        for host in self.hosts:
            if host.hostname == hostname:
                return host
        return None
