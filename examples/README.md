
## Examples
To try most important API functions in some basic use-case there are example applications that can be used either on
their own or with the **examples.yang** module. To use this module you first need to install it using
`sysrepoctl -i examples.yang`. Then the following specific examples should work.

### Configuration Data

```
application_changes_example examples
```
This will listen for configuration changes in *<running>* of the *examples* module. It will also block the terminal,
so use another one to continue.
___

```
sr_set_item_example /examples:cont/l value
```
This will set */examples:cont/l* to *value*. You should see information about this in the first terminal.

### Operational State Data

```
oper_data_pull_example examples /examples:stats
```
This will subscribe for providing *<operational>* data */examples:stats* in the *examples* module. Use another terminal
to request the data.
___
```
sr_get_items_example /examples:*//. operational
```
This will request all *<operational>* data of the *examples* module.

### RPCs

```
rpc_subscribe_example /examples:oper
```
This will subscribe for handling RPC */examples:oper* and only for this RPC it also generates some output. Use another
terminal to send the RPC.
___
```
rpc_send_example /examples:oper
```
This will send the RPC */examples:oper*. You should see it being received in the first terminal and also
the returned output.

### Notifications

```
notif_subscribe_example examples
```
This will subscribe for all notifications from the *examples* module received. Another argument can be specified
to filter them. Use another terminal to send the notification.
___
```
notif_send_example /examples:notif val 25.22
```
This will send the notification */examples:notif* with input value *val* set to *25.22*. You should see it being
received in the first terminal.
