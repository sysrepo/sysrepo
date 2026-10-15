# notifd_client - UDP Notif Receiver Example

A simple example client that receives YANG notifications over the
UDP-Notif transport protocol from sysrepo-notifd.
It listens on a configurable UDP port, decodes the notification payload,
and prints each notification to stdout. It is built on the UDP-Notif
collector from `<sysrepo/udp_notif.h>` and can serve as a starting point
for a custom receiver.

## Usage

```
notifd_client <port> [options]

Arguments:
  port          UDP port to listen on

Options:
  -h            Show help
  -a <addr>     IPv4 or IPv6 address to bind to (default any)
  -t <ms>       Receive timeout in milliseconds (default 5000, 0 for infinite)
```

Example:

```bash
# Start the client listening on UDP port 47950
$ notifd_client 47950
```

Then start sysrepo-notifd and configure subscriptions (see below).

## Configuring Subscriptions

For the client to receive notifications, a configured subscription must
be created in the sysrepo running datastore that references a UDP-Notif
receiver instance pointing to the client's UDP port.

### Example: Subscribe to NETCONF stream notifications

Using `sysrepocfg` or programmatically via sysrepo API, set the
following data in the running datastore:

```xml
<subscriptions xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
  <receiver-instances xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers">
    <receiver-instance>
      <name>my-udp-receiver</name>
      <udp-notif-receiver xmlns="urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport">
        <remote-address>127.0.0.1</remote-address>
        <remote-port>47950</remote-port>
        <enable-segmentation>true</enable-segmentation>
        <max-segment-size>1400</max-segment-size>
      </udp-notif-receiver>
    </receiver-instance>
  </receiver-instances>
  <subscription>
    <id>1</id>
    <stream>NETCONF</stream>
    <transport xmlns:unt="urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport">unt:udp-notif</transport>
    <receivers>
      <receiver>
        <name>recv1</name>
        <receiver-instance-ref xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers">my-udp-receiver</receiver-instance-ref>
      </receiver>
    </receivers>
  </subscription>
</subscriptions>
```

This example XML data is stored in `example_sn_data.xml`. To apply it to the running
datastore using `sysrepocfg`:

```bash
$ sysrepocfg -E ../examples/notifd/example_sn_data.xml
```

This creates:

- A **receiver instance** named `my-udp-receiver` that tells
  sysrepo-notifd to send UDP-Notif messages to `127.0.0.1:47950`.
- A **subscription** with ID 1 that subscribes to the `NETCONF`
  stream using the `udp-notif` transport, referencing the receiver
  instance above.

Once applied, sysrepo-notifd will send a `subscription-started`
notification to the client, followed by any NETCONF stream events.
You can use the `notif_send_example` binary to trigger test
notifications and verify they arrive at the client.

To terminate the configured subscription, you can just delete it
from the datastore. For example using `sysrepocfg`:

```bash
$ echo '<subscriptions xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"/>' | sysrepocfg -I --
```

### Adding an XPath filter

To receive only `netconf-config-change` notifications, add an
XPath filter to the subscription:

```xml
<stream-xpath-filter>/ietf-netconf-notifications:netconf-config-change</stream-xpath-filter>
```

Place this inside the `<subscription>` element.

### Example: YANG Push subscriptions

Instead of a stream, a subscription can select data of a datastore
and push it to the receiver (RFC 8641). The examples below push the
interfaces of the running datastore, so load some first:

```bash
$ sysrepocfg -E ../examples/notifd/example_interfaces.xml -m ietf-interfaces
```

A periodic subscription, `example_yp_periodic.xml`, sends the data
every 5 seconds:

```bash
$ sysrepocfg -E ../examples/notifd/example_yp_periodic.xml -m ietf-subscribed-notifications
```

The client receives `subscription-started` followed by a `push-update`
with the selected data every period.

An on-change subscription, `example_yp_on_change.xml`, sends the data
once when it starts and then every change of it:

```bash
$ sysrepocfg -E ../examples/notifd/example_yp_on_change.xml -m ietf-subscribed-notifications
```

The client receives `subscription-started` and a `push-update`, then a
`push-change-update` with a YANG patch for every edit of the data, for
example after changing the interface description with:

```bash
$ sysrepocfg -E vim -m ietf-interfaces
```

### Prerequisites

If you have sysrepo installed, the required modules are already
available and no extra steps are needed. Otherwise, ensure the
following YANG modules are installed in sysrepo:

- `ietf-subscribed-notifications` (with features: `configured`, `xpath`, `replay`, `subtree`)
- `ietf-subscribed-notif-receivers`
- `ietf-udp-notif-transport`
- `ietf-yang-push` (with feature: `on-change`) and `ietf-yang-patch`, for YANG Push

Use `sysrepoctl` to install them if needed. The interfaces of the
YANG Push examples also need `iana-if-type`, which is not installed
with sysrepo:

```bash
$ sysrepoctl -i ../modules/subscribed_notifications/iana-if-type@2014-05-08.yang
```
