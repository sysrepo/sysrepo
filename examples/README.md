
## Examples
To try most important API functions in some basic use-case there are example applications that can be used either on their own or with the **examples.yang** module. To use this module you first need to install it using `sysrepoctl -i examples.yang`. Then the following specific examples should work.

### Configuration Data

```
application_changes_example examples
```
This will listen for configuration changes in *<running>* of the *examples* module. It will also block the terminal, so use another one to continue.
___

```
sr_set_item_example /examples:cont/l value
```
This will set */examples:cont/l* to *value*. You should see information about this in the first terminal.

### Operational State Data

```
oper_data_example examples /examples:stats
```
This will subscribe for providing *<operational>* data */examples:stats* in the *examples* module. Use another terminal to request the data.
___
```
sr_get_items_example /examples:*//. operational
```
This will request all *<operational>* data of the *examples* module.
