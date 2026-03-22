# Home Assistant MQTT Discovery Reference

This document is the authoritative reference for implementing an MQTT publisher that
integrates network host data into Home Assistant via MQTT Discovery.

## 1. MQTT Discovery Fundamentals

### Discovery Topic Format

```
<discovery_prefix>/<component>/[<node_id>/]<object_id>/config
```

| Part | Required | Description |
|------|----------|-------------|
| `discovery_prefix` | yes | Defaults to `homeassistant`. Configurable in HA MQTT options. |
| `component` | yes | The HA platform: `binary_sensor`, `sensor`, `device_tracker`, `switch`, `device` (for multi-component discovery), etc. |
| `node_id` | no | Organizational segment for topic hierarchy. Characters `[a-zA-Z0-9_-]` only. Not used by HA itself -- purely for structuring the MQTT topic namespace. |
| `object_id` | yes | Identifies this specific config entry. Characters `[a-zA-Z0-9_-]` only. Best practice: set this to the `unique_id` value. |
| `config` | yes | Literal suffix. |

Example topics:

```
homeassistant/binary_sensor/big-storage/connectivity/config
homeassistant/sensor/big-storage/rtt/config
homeassistant/device_tracker/big-storage/tracker/config
```

### Key Identifiers and How They Relate

There are four distinct name/ID concepts. Getting them right is critical for stable,
human-friendly entity management.

| Field | Purpose | Where It Appears | Persistence |
|-------|---------|------------------|-------------|
| `unique_id` | **Immutable internal identifier.** Ties the entity to the entity registry. Must be globally unique within a platform (e.g., all `binary_sensor` entities). | Discovery payload JSON. | Permanent. Never change it. |
| `object_id` (topic) | The `<object_id>` segment in the discovery topic path. | MQTT topic only. | Used for discovery routing. Best practice: set equal to `unique_id`. |
| `name` | **Display name** of the entity. Combined with device name for `friendly_name`. | Discovery payload JSON. | Can be changed freely without breaking automations. |
| `default_entity_id` | Overrides the auto-generated `entity_id`. Full domain-qualified form: `sensor.my_entity`. Only used on first discovery. | Discovery payload JSON. | Initial assignment only. |

**Deprecated:** The `object_id` JSON field (not the topic segment) is deprecated in favour
of `default_entity_id`. It will stop working in HA Core 2026.4.

### How HA Derives entity_id

The `entity_id` is the slug used in automations, templates, and the API
(e.g., `binary_sensor.big_storage_connectivity`). The derivation rules:

1. **Entity not part of a device:** `entity_id = {domain}.{entity_name_slug}`
2. **Entity part of a device, with a name:** `entity_id = {domain}.{device_name_slug}_{entity_name_slug}`
3. **Entity part of a device, name is `null`:** `entity_id = {domain}.{device_name_slug}`

Where `slug` means: lowercased, spaces/hyphens replaced with underscores, special characters stripped.

If `default_entity_id` is set (e.g., `"default_entity_id": "sensor.big_storage_rtt"`), it
overrides the auto-generated value on first discovery only.

**Gotcha:** Once an entity is registered, its `entity_id` is stored in the entity registry
and won't change even if you update `name` or `default_entity_id` in subsequent discovery
messages. Users can rename entity_ids manually in the UI. The `unique_id` is the only
permanent link.

### How HA Derives friendly_name

The `friendly_name` is the human-readable label shown in the UI. When
`has_entity_name` is `true` (automatically set for all MQTT entities since HA 2023.8):

| Scenario | friendly_name |
|----------|---------------|
| Entity has device + entity name | `"{device.name} {entity.name}"` |
| Entity has device, name is `null` | `"{device.name}"` (main feature of device) |
| Entity has no device | `"{entity.name}"` |

**Rule:** The entity `name` should identify only the data point ("Connectivity", "RTT",
"IP Address"), never include the device name. HA prepends the device name automatically.

**Setting name to `null`:** Marks the entity as the "main feature" of the device. Only one
entity per device should do this. Example: a connectivity binary_sensor could be the main
feature of a network host device.

### Naming Entities Without a device_class

Unnamed `binary_sensor`, `button`, `number`, and `sensor` entities are automatically named
after their `device_class`. For example, a binary_sensor with `device_class: connectivity`
and no explicit `name` will be named "Connectivity" automatically.

If there is no `device_class` and no `name`, the entity gets a generic name like
"MQTT Sensor". Always set either `name` or `device_class` (or both).


## 2. Device Registry via MQTT

### The `device` Dict

Every discovery payload should include a `device` dict to register the entity's device in
the HA device registry. Multiple entities sharing the same device `identifiers` or
`connections` are grouped under one device.

```json
{
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"],
    "connections": [["mac", "aa:bb:cc:dd:ee:ff"]],
    "name": "big-storage",
    "manufacturer": "Supermicro",
    "model": "X11SCL-F",
    "hw_version": "1.0",
    "sw_version": "Ubuntu 22.04",
    "serial_number": "S123456",
    "configuration_url": "https://big-storage.welland.mithis.com",
    "suggested_area": "Server Room",
    "via_device": "gdoc2netcfg_switch1"
  }
}
```

| Field | Abbrev. | Required | Description |
|-------|---------|----------|-------------|
| `identifiers` | `ids` | * | List of unique device IDs. A string or list of strings. |
| `connections` | `cns` | * | List of `[type, value]` tuples. Only `"mac"` is a well-defined type. |
| `name` | `name` | yes | Human-readable device name. |
| `manufacturer` | `mf` | no | Device manufacturer. |
| `model` | `mdl` | no | Device model. |
| `model_id` | `mdl_id` | no | Machine-readable model identifier. |
| `hw_version` | `hw` | no | Hardware version string. |
| `sw_version` | `sw` | no | Software/firmware version string. |
| `serial_number` | `sn` | no | Serial number. |
| `configuration_url` | `cu` | no | URL for device configuration page. Shows as a link on the device page. |
| `suggested_area` | `sa` | no | Suggested HA area (e.g., "Server Room"). Applied on first discovery only. |
| `via_device` | — | no | Identifier of a parent/hub device. Must match an `identifiers` value of another device. |

*At least one of `identifiers` or `connections` is required.

### `identifiers` vs `connections`

**`identifiers`** are opaque strings scoped to the integration. Two MQTT discovery
messages with the same identifier value are grouped under one device. Identifiers do NOT
merge devices across different integrations.

**`connections`** are typed tuples that can merge devices across integrations. If an MQTT
device declares `"connections": [["mac", "aa:bb:cc:dd:ee:ff"]]` and a different integration
(e.g., UniFi) also knows a device with that MAC, HA may merge them into one device page.

**Recommendation for network monitoring:** Use both. Set `identifiers` to a namespaced
string like `"gdoc2netcfg_{machine_name}"` for guaranteed MQTT-internal grouping. Add
`connections` with the MAC address if you want cross-integration device merging (e.g.,
merging with Fritz!Box or UniFi device tracker entries for the same physical device).

```json
{
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"],
    "connections": [
      ["mac", "aa:bb:cc:dd:ee:ff"],
      ["mac", "aa:bb:cc:dd:ee:00"]
    ],
    "name": "big-storage"
  }
}
```

### Multiple Entities Under One Device

Publishing multiple discovery messages with matching `device.identifiers` groups all the
resulting entities under a single device page. Each message creates one entity:

```
homeassistant/binary_sensor/big-storage/connectivity/config  -> connectivity entity
homeassistant/sensor/big-storage/rtt/config                  -> RTT sensor entity
homeassistant/sensor/big-storage/ip_address/config           -> IP address entity
```

All three payloads include the same `"device": {"identifiers": ["gdoc2netcfg_big-storage"]}`.
The device page in HA shows all three entities.

### `via_device` for Network Topology

`via_device` expresses "this device communicates through that device." It takes a single
identifier string that must match an `identifiers` value of another already-discovered
device.

```json
{
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"],
    "name": "big-storage",
    "via_device": "gdoc2netcfg_switch1"
  }
}
```

On the HA device page for `switch1`, the "connected devices" section will show
`big-storage`. This is useful for expressing switch-to-host and gateway-to-device topology.

**Limitation:** `via_device` is purely informational in the UI. It does NOT affect
availability, state, or automations. A device does not become unavailable when its
`via_device` parent goes offline.

### The `origin` Dict

Recommended (required for device-type discovery). Identifies the software publishing the
discovery messages. Logged in the HA core event log.

```json
{
  "origin": {
    "name": "gdoc2netcfg",
    "sw": "1.0.0",
    "url": "https://github.com/mithro/gdoc2netcfg"
  }
}
```

Abbreviated form uses `o` for `origin`, `sw` for `sw_version`, `url` for `support_url`.


## 3. Entity Types for Network Monitoring

### binary_sensor with device_class: connectivity

The primary entity for "is this host reachable?" monitoring.

**Discovery topic:**
```
homeassistant/binary_sensor/big-storage/connectivity/config
```

**Discovery payload:**
```json
{
  "name": "Connectivity",
  "unique_id": "gdoc2netcfg_big-storage_connectivity",
  "device_class": "connectivity",
  "state_topic": "gdoc2netcfg/big-storage/connectivity/state",
  "payload_on": "ON",
  "payload_off": "OFF",
  "availability": [
    {
      "topic": "gdoc2netcfg/bridge/availability",
      "payload_available": "online",
      "payload_not_available": "offline"
    }
  ],
  "expire_after": 300,
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"],
    "connections": [["mac", "aa:bb:cc:dd:ee:ff"]],
    "name": "big-storage",
    "manufacturer": "Supermicro",
    "model": "X11SCL-F",
    "configuration_url": "https://big-storage.welland.mithis.com",
    "suggested_area": "Server Room",
    "via_device": "gdoc2netcfg_switch1"
  },
  "origin": {
    "name": "gdoc2netcfg",
    "sw": "1.0.0",
    "url": "https://github.com/mithro/gdoc2netcfg"
  }
}
```

**State topic publishes:** `ON` when host responds to ping, `OFF` when it does not.

**In the UI:** Shows "Connected" / "Disconnected" with appropriate icons.

### sensor with device_class: duration (RTT)

Round-trip time as a measurement sensor with long-term statistics.

**Discovery topic:**
```
homeassistant/sensor/big-storage/rtt/config
```

**Discovery payload:**
```json
{
  "name": "Round-trip time",
  "unique_id": "gdoc2netcfg_big-storage_rtt",
  "device_class": "duration",
  "state_class": "measurement",
  "unit_of_measurement": "ms",
  "suggested_display_precision": 1,
  "state_topic": "gdoc2netcfg/big-storage/rtt/state",
  "value_template": "{{ value_json.avg }}",
  "json_attributes_topic": "gdoc2netcfg/big-storage/rtt/state",
  "json_attributes_template": "{{ value_json | tojson }}",
  "availability": [
    {
      "topic": "gdoc2netcfg/big-storage/connectivity/state",
      "payload_available": "ON",
      "payload_not_available": "OFF"
    }
  ],
  "entity_category": "diagnostic",
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"]
  },
  "origin": {
    "name": "gdoc2netcfg"
  }
}
```

**State topic publishes:**
```json
{"avg": 1.2, "min": 0.8, "max": 2.1, "mdev": 0.3, "transmitted": 5, "received": 5}
```

The `value_template` extracts the primary value (average RTT). The
`json_attributes_topic`/`json_attributes_template` pair stores the full detail as entity
attributes visible in Developer Tools > States and on the entity detail page.

**Long-term statistics:** Because `state_class: measurement` is set, HA automatically
records 5-minute snapshots (min/max/mean) and hourly aggregates. These appear in the
Statistics graph card.

### sensor with no device_class (IP address, MAC address)

For informational string values that aren't measurements.

**Discovery topic:**
```
homeassistant/sensor/big-storage/ip_address/config
```

**Discovery payload:**
```json
{
  "name": "IP address",
  "unique_id": "gdoc2netcfg_big-storage_ip_address",
  "state_topic": "gdoc2netcfg/big-storage/attributes/state",
  "value_template": "{{ value_json.ip }}",
  "entity_category": "diagnostic",
  "icon": "mdi:ip-network",
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"]
  },
  "origin": {
    "name": "gdoc2netcfg"
  }
}
```

**State topic publishes:**
```json
{"ip": "10.1.20.100", "ipv6": "2404:e80:a137:120::100", "mac": "aa:bb:cc:dd:ee:ff"}
```

**Note:** Sensors without `device_class` and without `state_class` do NOT get long-term
statistics. They store current state only. This is appropriate for IP/MAC values that
rarely change.

### device_tracker for Network Presence

Creates a device tracker entity that feeds into the Person integration.

**Discovery topic:**
```
homeassistant/device_tracker/big-storage/tracker/config
```

**Discovery payload:**
```json
{
  "name": "Network presence",
  "unique_id": "gdoc2netcfg_big-storage_tracker",
  "state_topic": "gdoc2netcfg/big-storage/tracker/state",
  "source_type": "router",
  "payload_home": "home",
  "payload_not_home": "not_home",
  "json_attributes_topic": "gdoc2netcfg/big-storage/tracker/attributes",
  "availability": [
    {
      "topic": "gdoc2netcfg/bridge/availability",
      "payload_available": "online",
      "payload_not_available": "offline"
    }
  ],
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"],
    "connections": [["mac", "aa:bb:cc:dd:ee:ff"]],
    "name": "big-storage"
  },
  "origin": {
    "name": "gdoc2netcfg"
  }
}
```

**State topic publishes:** `home` or `not_home`

**Attributes topic publishes:**
```json
{
  "ip": "10.1.20.100",
  "mac": "aa:bb:cc:dd:ee:ff",
  "host_name": "big-storage"
}
```


## 4. Availability System

### Concept: Three Distinct States

HA entities have three possible conditions, and understanding the distinction is critical:

| Condition | Meaning | When It Applies |
|-----------|---------|-----------------|
| **Available + ON/value** | The entity is reachable and reporting a known state. | Normal operation. |
| **Available + OFF/value** | The entity is reachable and reports it is off/disconnected. | Host is down but the monitoring system is up. |
| **Unavailable** | The entity cannot be reached. No state is known. | The monitoring system itself is down, or `expire_after` triggered. |

For a connectivity binary_sensor:
- **ON** = host is responding to ping (Connected)
- **OFF** = host is not responding to ping (Disconnected)
- **Unavailable** = the MQTT publisher is not running / hasn't reported in time

### Single Topic vs Topic List

**Single topic** (simple case):
```json
{
  "availability_topic": "gdoc2netcfg/bridge/availability",
  "payload_available": "online",
  "payload_not_available": "offline"
}
```

**Multiple topics** (for compound conditions):
```json
{
  "availability": [
    {
      "topic": "gdoc2netcfg/bridge/availability",
      "payload_available": "online",
      "payload_not_available": "offline"
    },
    {
      "topic": "gdoc2netcfg/big-storage/plug/state",
      "payload_available": "ON",
      "payload_not_available": "OFF"
    }
  ],
  "availability_mode": "all"
}
```

**`availability_topic` and `availability` (list) are mutually exclusive.** You cannot use
both.

### availability_mode

Controls how multiple topics combine:

| Mode | Behavior |
|------|----------|
| `all` | Entity is available only when ALL topics report available. |
| `any` | Entity is available when ANY topic reports available. |
| `latest` (default) | Last received message determines availability. |

### expire_after

`expire_after` sets a timeout in seconds. If no state update is received within this
period, the entity becomes **unavailable**. This is the primary mechanism for detecting
when the MQTT publisher stops running.

```json
{
  "expire_after": 300,
  "state_topic": "gdoc2netcfg/big-storage/connectivity/state"
}
```

If the publisher sends connectivity updates every 60 seconds and sets `expire_after: 300`,
the entity goes unavailable after 5 minutes of silence.

**Gotcha:** `expire_after` applies to state messages, not availability messages. It counts
seconds since the last message on `state_topic`. If availability is defined separately, the
entity follows availability topic rules AND the expire_after timeout.

**Gotcha:** `expire_after` is supported on `sensor` and `binary_sensor` entities. It is NOT
supported on `device_tracker`.

### Availability on Startup

When `availability` is configured, the entity starts as **unavailable** until it receives
its first availability payload. Without `availability` configured, the entity starts as
available with an **unknown** state.

### Using Availability for Power Dependencies

You can express "Device B depends on Plug A being on" by including the plug's state topic
in Device B's availability list:

```json
{
  "availability": [
    {
      "topic": "gdoc2netcfg/bridge/availability",
      "payload_available": "online",
      "payload_not_available": "offline"
    },
    {
      "topic": "homeassistant/switch/plug-a/state",
      "payload_available": "ON",
      "payload_not_available": "OFF"
    }
  ],
  "availability_mode": "all"
}
```

When the plug is OFF, Device B's entities become unavailable. This is a convention -- HA
does not natively understand "powers" relationships, but the availability system can model
the practical effect.


## 5. Device Tracker vs Binary Sensor for Presence

### When to Use Each

| | device_tracker | binary_sensor (connectivity) |
|-|----------------|------------------------------|
| **Purpose** | Track where a device IS (home/away/zone) | Track whether a device is reachable |
| **States** | `home`, `not_home`, zone names | `ON` (connected), `OFF` (disconnected) |
| **Person integration** | Yes -- feeds into Person for combined presence | No -- cannot be assigned to a Person |
| **Zone support** | Yes -- can report GPS or zone names | No |
| **source_type** | `router`, `gps`, `bluetooth`, `bluetooth_le` | N/A |
| **Device class** | N/A | `connectivity` |
| **Long-term stats** | No | No (binary state) |
| **Consider home** | Configurable delay before marking away | N/A |
| **Best for** | People/phone tracking, room presence | Infrastructure monitoring, host up/down |

### How Fritz!Box, UniFi Model Network Devices

**Fritz!Box integration** creates:
- `device_tracker` entity per connected client (source_type: router)
- `binary_sensor` for connectivity
- `switch` for parental controls
- Updates every 30 seconds
- Configurable "consider home" timeout

**UniFi integration** creates:
- `device_tracker` entity per connected client (source_type: router)
- `sensor` entities for bandwidth (TX/RX), uptime, link speed
- Port link speed sensors for switch ports

Both use `device_tracker` with `source_type: router` for network presence, NOT
`binary_sensor`. This is because `device_tracker` entities can be assigned to `Person`
entities for combined multi-source presence detection.

### Person Integration

The Person integration combines multiple device_tracker entities using priority logic:

1. Stationary trackers (source_type: `router`, `bluetooth`) are checked first when home
2. GPS trackers are preferred when away from home
3. Most recently updated tracker wins within each category

For network monitoring (non-person devices like servers and switches), `binary_sensor`
with `device_class: connectivity` is more appropriate. `device_tracker` is designed for
things that move between zones.

### MQTT Discovery for device_tracker

Yes, MQTT discovery can create `device_tracker` entities. Publish to:
```
homeassistant/device_tracker/{object_id}/config
```

Key fields:
- `source_type`: `"router"` for network-based detection
- `state_topic`: publishes `home` or `not_home`
- `payload_home` / `payload_not_home`: customizable payloads (defaults: `home` / `not_home`)
- `payload_reset`: resets to zone-based location detection
- `json_attributes_topic`: can publish `ip`, `mac`, `host_name`, GPS data

### ScannerEntity vs TrackerEntity (Internal Architecture)

At the developer level, HA has two device_tracker base classes:

- **ScannerEntity**: For local network connectivity (is_connected = home/not_home).
  Properties: `is_connected`, `ip_address`, `mac_address`, `hostname`, `battery_level`.
  Default source_type: `router`.

- **TrackerEntity**: For GPS/location tracking.
  Properties: `latitude`, `longitude`, `location_name`, `location_accuracy`, `battery_level`.
  Default source_type: `gps`.

MQTT device_tracker maps most closely to ScannerEntity when used with `source_type: router`.


## 6. Stable Entity IDs

### The Problem

If you rename a device or entity, you don't want automations to break. Entity IDs must be
stable across config changes.

### The Solution

1. **Set `unique_id` to a permanent, never-changing identifier.** Base it on something
   immutable like `{integration_name}_{machine_name}_{entity_type}`. Example:
   `"gdoc2netcfg_big-storage_connectivity"`

2. **Keep `unique_id` the same forever.** Even if the device display name changes, the
   `unique_id` anchors the entity in the registry.

3. **Use `name` freely for display purposes.** Changing `name` updates the `friendly_name`
   in the UI but does NOT change the `entity_id` (which was set on first discovery).

4. **Use `default_entity_id` for predictable initial entity_ids.** Set it to the
   full domain-qualified form: `"default_entity_id": "binary_sensor.big_storage_connectivity"`.
   This is only used on first discovery.

5. **Set the topic `<object_id>` to the `unique_id` value.** This is the documented best
   practice.

### What NOT to Do

- Don't change `unique_id` -- that creates a new entity and orphans the old one.
- Don't rely on `name` for entity_id stability -- `name` is for display only.
- Don't use `object_id` (the JSON field) -- it's deprecated. Use `default_entity_id`.
- Don't include the device name in the entity `name` -- HA prepends it automatically.


## 7. JSON Attributes

### json_attributes_topic and json_attributes_template

These fields let you attach rich metadata to an entity as key-value attributes.

```json
{
  "state_topic": "gdoc2netcfg/big-storage/rtt/state",
  "value_template": "{{ value_json.avg }}",
  "json_attributes_topic": "gdoc2netcfg/big-storage/rtt/state",
  "json_attributes_template": "{{ value_json | tojson }}"
}
```

**Same topic for state and attributes:** Yes, `state_topic` and `json_attributes_topic` can
point to the same MQTT topic. Use `value_template` to extract the primary state value, and
`json_attributes_template` to extract the full JSON as attributes.

**State topic publishes:**
```json
{"avg": 1.2, "min": 0.8, "max": 2.1, "mdev": 0.3, "transmitted": 5, "received": 5, "loss_pct": 0.0}
```

The entity state becomes `1.2` (the avg). The attributes become:
```
avg: 1.2
min: 0.8
max: 2.1
mdev: 0.3
transmitted: 5
received: 5
loss_pct: 0.0
```

### Where Attributes Appear

- **Entity detail page** in HA UI (click the entity)
- **Developer Tools > States** page
- **Templates** via `state_attr('sensor.big_storage_rtt', 'min')`
- They do NOT appear as separate entries in the device page (only entities show there)
- Attributes are NOT recorded in long-term statistics (only the main state value is)


## 8. State Classes and Device Classes

### Binary Sensor Device Classes (Relevant to Network Monitoring)

| device_class | ON meaning | OFF meaning | Icon |
|-------------|------------|-------------|------|
| `connectivity` | Connected | Disconnected | network icon |
| `plug` | Plugged in | Unplugged | plug icon |
| `power` | Power detected | No power | power icon |
| `problem` | Problem detected | No problem | alert icon |
| `running` | Running | Not running | play icon |
| `presence` | Home | Away | person icon |

### Sensor Device Classes (Relevant to Network Monitoring)

| device_class | Units | Use Case |
|-------------|-------|----------|
| `duration` | d, h, min, s, ms | Round-trip time, uptime |
| `timestamp` | ISO 8601 datetime | Last seen, last boot |
| `data_rate` | bit/s, kbit/s, Mbit/s, Gbit/s, B/s, kB/s, MB/s, GB/s | Interface throughput |
| `data_size` | B, kB, MB, GB, TB (+ binary: KiB, MiB, GiB, etc.) | Data transferred |
| `signal_strength` | dB, dBm | WiFi signal, SNMP signal |

### State Classes

State classes control long-term statistics recording and graph rendering.

| state_class | Use Case | Statistics Stored | Graph Style |
|-------------|----------|-------------------|-------------|
| `measurement` | Point-in-time readings (RTT, temperature) | min/max/mean per 5min + hourly | Line chart |
| `total` | Cumulative values that can go up and down (net metering) | Sum per period | Line chart |
| `total_increasing` | Monotonically increasing counters (bytes transferred) | Sum per period; negative delta = reset | Line chart |
| `measurement_angle` | Angular values (wind direction) | min/max/mean | Line chart |

**For RTT monitoring:** Use `state_class: measurement` + `device_class: duration` +
`unit_of_measurement: ms`. This gives you automatic long-term statistics with min/max/mean
aggregation.

**For packet loss percentage:** Use `state_class: measurement` +
`unit_of_measurement: %`. No device_class needed.

**For IP/MAC address strings:** Don't set `state_class` at all. These are not measurements.

### entity_category

Controls where entities appear in the UI:

| entity_category | Meaning | UI Placement |
|-----------------|---------|--------------|
| (not set) | Primary entity | Main entity list on device page |
| `"diagnostic"` | Informational/read-only | "Diagnostic" section, collapsed by default |
| `"config"` | User-configurable setting | "Configuration" section |

**For network monitoring:** Use `"diagnostic"` for IP address, MAC address, VLAN, firmware
version sensors. Leave connectivity and RTT without entity_category (or use diagnostic for
RTT if connectivity is the primary entity).

### enabled_by_default

Set `"enabled_by_default": false` to create entities in a disabled state. Users must
manually enable them. Good for verbose per-interface sensors that most users won't need.


## 9. Discovery Lifecycle

### Creating Entities

Publish a JSON payload to the config topic with retain flag set:

```bash
mosquitto_pub -h broker -t "homeassistant/binary_sensor/big-storage/connectivity/config" \
  -r -m '{"name":"Connectivity","unique_id":"gdoc2netcfg_big-storage_conn",...}'
```

### Updating Entities

Publish a new payload to the same config topic. HA applies the changes. You can update
`name`, `device` metadata, `availability` configuration, etc. You MUST NOT change
`unique_id`.

### Removing Entities

Publish an empty retained payload to the config topic:

```bash
mosquitto_pub -h broker -t "homeassistant/binary_sensor/big-storage/connectivity/config" \
  -r -n
```

The empty payload removes the entity and clears the retained message at the broker.

### Retain Flag Strategy

**Discovery config topics:** ALWAYS retain. Without retain, HA loses all entities on restart
and won't rediscover them until the publisher re-sends.

**State topics:** Do NOT retain. Retained state messages cause stale data to replay on HA
restart. Let the publisher send fresh state on its next cycle.

**Availability topics:** Retain the availability topic so HA knows the current state
immediately on startup. Use MQTT Last Will and Testament (LWT) for the publisher's own
availability topic.

### Birth Message Protocol

HA publishes `online` to `homeassistant/status` (configurable) when its MQTT integration
starts. Devices/publishers should:

1. Subscribe to `homeassistant/status`
2. When `online` is received, re-publish all discovery payloads
3. Optionally add a small random delay to avoid broker overload

This is the recommended approach in addition to (not instead of) retained discovery
messages. It handles edge cases where the broker lost retained messages.


## 10. Multi-Component Device Discovery

Since HA 2024.x, you can publish all entities for a device in a single discovery message
using the `device` component type.

**Discovery topic:**
```
homeassistant/device/big-storage/config
```

**Discovery payload:**
```json
{
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"],
    "connections": [["mac", "aa:bb:cc:dd:ee:ff"]],
    "name": "big-storage",
    "manufacturer": "Supermicro",
    "model": "X11SCL-F",
    "configuration_url": "https://big-storage.welland.mithis.com",
    "suggested_area": "Server Room",
    "via_device": "gdoc2netcfg_switch1"
  },
  "origin": {
    "name": "gdoc2netcfg",
    "sw": "1.0.0",
    "url": "https://github.com/mithro/gdoc2netcfg"
  },
  "components": {
    "connectivity": {
      "platform": "binary_sensor",
      "unique_id": "gdoc2netcfg_big-storage_connectivity",
      "name": null,
      "device_class": "connectivity",
      "state_topic": "gdoc2netcfg/big-storage/connectivity/state",
      "payload_on": "ON",
      "payload_off": "OFF",
      "expire_after": 300
    },
    "rtt": {
      "platform": "sensor",
      "unique_id": "gdoc2netcfg_big-storage_rtt",
      "name": "Round-trip time",
      "device_class": "duration",
      "state_class": "measurement",
      "unit_of_measurement": "ms",
      "suggested_display_precision": 1,
      "state_topic": "gdoc2netcfg/big-storage/rtt/state",
      "value_template": "{{ value_json.avg }}",
      "json_attributes_topic": "gdoc2netcfg/big-storage/rtt/state",
      "json_attributes_template": "{{ value_json | tojson }}",
      "entity_category": "diagnostic"
    },
    "ip_address": {
      "platform": "sensor",
      "unique_id": "gdoc2netcfg_big-storage_ip_address",
      "name": "IP address",
      "state_topic": "gdoc2netcfg/big-storage/attributes/state",
      "value_template": "{{ value_json.ipv4 }}",
      "entity_category": "diagnostic",
      "icon": "mdi:ip-network"
    },
    "mac_address": {
      "platform": "sensor",
      "unique_id": "gdoc2netcfg_big-storage_mac_address",
      "name": "MAC address",
      "state_topic": "gdoc2netcfg/big-storage/attributes/state",
      "value_template": "{{ value_json.mac }}",
      "entity_category": "diagnostic",
      "icon": "mdi:ethernet"
    }
  },
  "state_topic": "gdoc2netcfg/big-storage/connectivity/state",
  "availability": [
    {
      "topic": "gdoc2netcfg/bridge/availability",
      "payload_available": "online",
      "payload_not_available": "offline"
    }
  ]
}
```

**Key differences from per-entity discovery:**
- Topic uses `device` as the component: `homeassistant/device/{object_id}/config`
- The `origin` field is required (not just recommended)
- Components are keyed under `"components"` (abbreviated `"cmps"`)
- Each component must have `"platform"` (abbreviated `"p"`) identifying the entity type
- Each entity component must have a `unique_id`
- The component key (e.g., `"connectivity"`, `"rtt"`) becomes part of the internal
  discovery identification
- Shared options like `availability` and `state_topic` can be set at root level and
  inherited by components

**When to use:** Multi-component discovery reduces MQTT message count and avoids repeating
the `device` dict in every message. Prefer it when publishing many entities per device.
The per-entity approach is simpler for a small number of entities or when entities are
published independently.


## 11. Common Abbreviations

For compact payloads, HA supports abbreviated field names:

| Full Name | Abbreviation |
|-----------|-------------|
| `availability` | `avty` |
| `availability_mode` | `avty_mode` |
| `availability_topic` | `avty_t` |
| `availability_template` | `avty_tpl` |
| `command_topic` | `cmd_t` |
| `components` | `cmps` |
| `connections` | `cns` |
| `configuration_url` | `cu` |
| `default_entity_id` | `def_eid` |
| `device` | `dev` |
| `device_class` | `dev_cla` |
| `entity_category` | `ent_cat` |
| `expire_after` | `exp_aft` |
| `hw_version` | `hw` |
| `identifiers` | `ids` |
| `json_attributes_template` | `json_attr_tpl` |
| `json_attributes_topic` | `json_attr_t` |
| `manufacturer` | `mf` |
| `model` | `mdl` |
| `model_id` | `mdl_id` |
| `name` | `name` |
| `origin` | `o` |
| `payload_available` | `pl_avail` |
| `payload_not_available` | `pl_not_avail` |
| `payload_off` | `pl_off` |
| `payload_on` | `pl_on` |
| `platform` | `p` |
| `serial_number` | `sn` |
| `state_class` | `stat_cla` |
| `state_topic` | `stat_t` |
| `suggested_area` | `sa` |
| `suggested_display_precision` | `sug_dsp_pr` |
| `sw_version` | `sw` |
| `unique_id` | `uniq_id` |
| `unit_of_measurement` | `unit_of_meas` |
| `value_template` | `val_tpl` |

Full and abbreviated forms can be mixed within a single payload.


## 12. Complete Practical Examples

### Example A: Network Host with Connectivity + Diagnostics

A server with a connectivity sensor (main entity), RTT sensor, and IP/MAC diagnostic
sensors all grouped under one device.

**Step 1: Connectivity binary_sensor (main entity)**

Topic: `homeassistant/binary_sensor/big-storage/connectivity/config`
```json
{
  "name": null,
  "unique_id": "gdoc2netcfg_big-storage_connectivity",
  "device_class": "connectivity",
  "state_topic": "gdoc2netcfg/big-storage/connectivity/state",
  "payload_on": "ON",
  "payload_off": "OFF",
  "expire_after": 300,
  "json_attributes_topic": "gdoc2netcfg/big-storage/ping/attributes",
  "json_attributes_template": "{{ value_json | tojson }}",
  "availability": [
    {
      "topic": "gdoc2netcfg/bridge/availability",
      "payload_available": "online",
      "payload_not_available": "offline"
    }
  ],
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"],
    "connections": [["mac", "aa:bb:cc:dd:ee:ff"]],
    "name": "big-storage",
    "manufacturer": "Supermicro",
    "model": "X11SCL-F",
    "hw_version": "Rev 1.02",
    "sw_version": "Ubuntu 22.04.3 LTS",
    "configuration_url": "https://big-storage.welland.mithis.com",
    "suggested_area": "Server Room",
    "via_device": "gdoc2netcfg_switch1"
  },
  "origin": {
    "name": "gdoc2netcfg",
    "sw": "1.0.0",
    "url": "https://github.com/mithro/gdoc2netcfg"
  }
}
```

With `"name": null`, this entity IS the device's main feature. Its `friendly_name` will
be just "big-storage" and its `entity_id` will be `binary_sensor.big_storage`.

**Step 2: RTT sensor (diagnostic)**

Topic: `homeassistant/sensor/big-storage/rtt/config`
```json
{
  "name": "Round-trip time",
  "unique_id": "gdoc2netcfg_big-storage_rtt",
  "device_class": "duration",
  "state_class": "measurement",
  "unit_of_measurement": "ms",
  "suggested_display_precision": 1,
  "state_topic": "gdoc2netcfg/big-storage/rtt/state",
  "value_template": "{{ value_json.avg }}",
  "json_attributes_topic": "gdoc2netcfg/big-storage/rtt/state",
  "json_attributes_template": "{{ value_json | tojson }}",
  "entity_category": "diagnostic",
  "expire_after": 300,
  "availability": [
    {
      "topic": "gdoc2netcfg/bridge/availability",
      "payload_available": "online",
      "payload_not_available": "offline"
    }
  ],
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"]
  },
  "origin": {
    "name": "gdoc2netcfg"
  }
}
```

`entity_id`: `sensor.big_storage_round_trip_time`
`friendly_name`: "big-storage Round-trip time"

**Step 3: IP address sensor (diagnostic)**

Topic: `homeassistant/sensor/big-storage/ip-address/config`
```json
{
  "name": "IPv4 address",
  "unique_id": "gdoc2netcfg_big-storage_ipv4_address",
  "state_topic": "gdoc2netcfg/big-storage/attributes/state",
  "value_template": "{{ value_json.ipv4 }}",
  "entity_category": "diagnostic",
  "icon": "mdi:ip-network",
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"]
  },
  "origin": {
    "name": "gdoc2netcfg"
  }
}
```

**Step 4: MAC address sensor (diagnostic)**

Topic: `homeassistant/sensor/big-storage/mac-address/config`
```json
{
  "name": "MAC address",
  "unique_id": "gdoc2netcfg_big-storage_mac_address",
  "state_topic": "gdoc2netcfg/big-storage/attributes/state",
  "value_template": "{{ value_json.mac }}",
  "entity_category": "diagnostic",
  "icon": "mdi:ethernet",
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"]
  },
  "origin": {
    "name": "gdoc2netcfg"
  }
}
```

**Runtime state publishing:**

```bash
# Connectivity state (every 60 seconds)
mosquitto_pub -t "gdoc2netcfg/big-storage/connectivity/state" -m "ON"

# Ping attributes (every 60 seconds, same cycle as connectivity)
mosquitto_pub -t "gdoc2netcfg/big-storage/ping/attributes" \
  -m '{"transmitted": 5, "received": 5, "loss_pct": 0.0}'

# RTT state (every 60 seconds, only when host is up)
mosquitto_pub -t "gdoc2netcfg/big-storage/rtt/state" \
  -m '{"avg": 1.23, "min": 0.81, "max": 2.14, "mdev": 0.31}'

# Static attributes (on startup and periodically)
mosquitto_pub -t "gdoc2netcfg/big-storage/attributes/state" \
  -m '{"ipv4": "10.1.20.100", "ipv6": "2404:e80:a137:120::100", "mac": "aa:bb:cc:dd:ee:ff", "vlan": 20}'

# Publisher availability (with LWT)
mosquitto_pub -t "gdoc2netcfg/bridge/availability" -r -m "online"
```


### Example B: Per-Interface Entities Under a Multi-NIC Host

For a host with two network interfaces, create sub-entities scoped to each interface.

Topic: `homeassistant/binary_sensor/big-storage/eth0-connectivity/config`
```json
{
  "name": "eth0",
  "unique_id": "gdoc2netcfg_big-storage_eth0_connectivity",
  "device_class": "connectivity",
  "state_topic": "gdoc2netcfg/big-storage/eth0/connectivity/state",
  "payload_on": "ON",
  "payload_off": "OFF",
  "expire_after": 300,
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"]
  },
  "origin": {
    "name": "gdoc2netcfg"
  }
}
```

`entity_id`: `binary_sensor.big_storage_eth0`
`friendly_name`: "big-storage eth0"

Topic: `homeassistant/binary_sensor/big-storage/eth1-connectivity/config`
```json
{
  "name": "eth1",
  "unique_id": "gdoc2netcfg_big-storage_eth1_connectivity",
  "device_class": "connectivity",
  "state_topic": "gdoc2netcfg/big-storage/eth1/connectivity/state",
  "payload_on": "ON",
  "payload_off": "OFF",
  "expire_after": 300,
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"]
  },
  "origin": {
    "name": "gdoc2netcfg"
  }
}
```

Both entities appear under the same device because they share `identifiers`.


### Example C: device_tracker for Network Presence

For a laptop that moves between home and away:

Topic: `homeassistant/device_tracker/tim-laptop/tracker/config`
```json
{
  "name": "Network presence",
  "unique_id": "gdoc2netcfg_tim-laptop_tracker",
  "state_topic": "gdoc2netcfg/tim-laptop/tracker/state",
  "source_type": "router",
  "payload_home": "home",
  "payload_not_home": "not_home",
  "json_attributes_topic": "gdoc2netcfg/tim-laptop/tracker/attributes",
  "availability": [
    {
      "topic": "gdoc2netcfg/bridge/availability",
      "payload_available": "online",
      "payload_not_available": "offline"
    }
  ],
  "device": {
    "identifiers": ["gdoc2netcfg_tim-laptop"],
    "connections": [["mac", "11:22:33:44:55:66"]],
    "name": "tim-laptop",
    "manufacturer": "Lenovo",
    "model": "ThinkPad X1 Carbon"
  },
  "origin": {
    "name": "gdoc2netcfg"
  }
}
```

**State publishing:**
```bash
# When device responds to ping
mosquitto_pub -t "gdoc2netcfg/tim-laptop/tracker/state" -m "home"

# With attributes
mosquitto_pub -t "gdoc2netcfg/tim-laptop/tracker/attributes" \
  -m '{"ip": "10.1.20.50", "mac": "11:22:33:44:55:66", "host_name": "tim-laptop"}'

# When device stops responding
mosquitto_pub -t "gdoc2netcfg/tim-laptop/tracker/state" -m "not_home"
```

This device_tracker can then be assigned to a Person entity in HA for presence automation.


### Example D: Availability Linked to Power Switch

A server powered by a smart plug. When the plug is off, the server's entities show
unavailable instead of showing misleading "disconnected" state.

The smart plug already exists in HA (e.g., via Tasmota) with state topic
`stat/server-plug/POWER`.

Topic: `homeassistant/binary_sensor/big-storage/connectivity/config`
```json
{
  "name": null,
  "unique_id": "gdoc2netcfg_big-storage_connectivity",
  "device_class": "connectivity",
  "state_topic": "gdoc2netcfg/big-storage/connectivity/state",
  "payload_on": "ON",
  "payload_off": "OFF",
  "expire_after": 300,
  "availability": [
    {
      "topic": "gdoc2netcfg/bridge/availability",
      "payload_available": "online",
      "payload_not_available": "offline"
    },
    {
      "topic": "stat/server-plug/POWER",
      "payload_available": "ON",
      "payload_not_available": "OFF"
    }
  ],
  "availability_mode": "all",
  "device": {
    "identifiers": ["gdoc2netcfg_big-storage"],
    "name": "big-storage",
    "via_device": "gdoc2netcfg_switch1"
  },
  "origin": {
    "name": "gdoc2netcfg"
  }
}
```

With `availability_mode: all`:
- Publisher online AND plug on = entity available (shows ON/OFF based on ping)
- Publisher online AND plug off = entity unavailable
- Publisher offline = entity unavailable


## 13. Gotchas and Common Mistakes

### Entity Name Includes Device Name
**Wrong:**
```json
{"device": {"name": "big-storage"}, "name": "big-storage Connectivity"}
```
Result: `friendly_name` = "big-storage big-storage Connectivity"

**Right:**
```json
{"device": {"name": "big-storage"}, "name": "Connectivity"}
```
Result: `friendly_name` = "big-storage Connectivity"

### Changing unique_id
Changing `unique_id` creates a new entity. The old entity becomes orphaned in the registry.
Users must manually delete the orphan. Never change `unique_id` once published.

### Forgetting retain on config topics
Without retain, HA loses all MQTT-discovered entities on restart. Always publish config
topics with the retain flag.

### Retaining state topics
Retained state messages replay stale data on HA restart. A host that was "ON" 3 days ago
will appear "ON" immediately after restart even if it's been down for days. Don't retain
state topics.

### Using expire_after on device_tracker
`expire_after` is not supported on `device_tracker` entities. For device_tracker timeout
behavior, use the `consider_home` setting on the Person entity or manage state transitions
in the publisher.

### availability vs expire_after
These are complementary, not alternatives:
- `availability` tracks whether the publisher/bridge is running
- `expire_after` catches the case where the publisher is running but stopped sending
  updates for this specific entity (e.g., a bug, a hung thread)

Use both for robust monitoring.

### MAC address format in connections
MAC addresses in `connections` must be in lowercase colon-separated format:
`"aa:bb:cc:dd:ee:ff"`. Invalid formats (uppercase, dash-separated, missing colons) may
silently fail to match devices across integrations.

### Multiple entities with name: null
Only one entity per device should have `"name": null` (the main feature). If multiple
entities set `name: null`, they'll all get the device name as their friendly_name, which
is confusing and may cause entity_id collisions.

### default_entity_id requires full domain
**Wrong:** `"default_entity_id": "big_storage_connectivity"`
**Right:** `"default_entity_id": "binary_sensor.big_storage_connectivity"`

### state_class on non-numeric sensors
Don't set `state_class: measurement` on sensors that report strings (IP addresses, MAC
addresses). HA will try to record statistics and fail.
