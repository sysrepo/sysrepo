# Sysrepo for Plugin Developers

## Introduction
This document will give an overview of Sysrepo and related projects, with a focus on plugin development.
To demonstrate how to work with Sysrepo when developing a plugin, we will use several existing plugins as examples.

### What is Sysrepo?

The first question that arises when talking about Sysrepo is, what exactly is Sysrepo? As described by the [official documentation](https://netopeer.liberouter.org/doc/sysrepo/master/index.html): “Sysrepo is a YANG-based datastore for Unix/Linux systems”. Like the name suggests, a datastore is a system used to store data, which can be implemented in many ways, for example by storing files, a database or other kinds of storage. In this case, the data is primarily configuration data for various applications. For example, the [DHCP plugin](https://github.com/sartura/dhcp/tree/devel) uses Sysrepo to store its configuration settings. Previously, most applications would have their own format and way of managing configuration data. One obvious difficulty with such an approach is the need to learn a new format when working with a new application. To solve that issue and provide a unified way to work with configurations, Sysrepo stores application configurations described in the YANG format. An example from the DHCP plugin YANG model is shown below.

```
leaf start {
    type uint32;
    Default “100”;
}
leaf stop {
    must “. >= ../start”;
    type uint32;
    default “250”;
}
```

The example defines the range of addresses that will be assigned from the DHCP server that is being managed. The full YANG model is included with the DHCP plugin and is available [here](https://github.com/sartura/dhcp/blob/devel/yang/terastream-dhcp%402017-12-07.yang). The DHCP plugin isn’t actually a DHCP server or client itself, but is responsible for mapping between YANG and UCI configuration data. UCI is a OpenWrt specific configuration system. The actual DHCP servers and clients on the system then read the UCI data and work with it, unaware of the DHCP plugin and Sysrepo. As previously mentioned, the DHCP plugin (and all other plugins mentioned in this text) is an example of the unification of configuration management that Sysrepo provides, which makes it easier to work with. The plugin synchronizes changes in both directions. If a change is made in the UCI configuration, it is transformed and stored into Sysrepo datastore and vice versa.


### Sysrepo and YANG
An important distinction to be made is that YANG models don’t contain the actual configuration data. As can be seen in the previous YANG example, the YANG model only describes what the configuration data should look like, e.g. the address range should go from 100 to 250. Actual configuration data would be stored as JSON or XML data, and would contain a concrete number. Sysrepo would then check whether the actual data is valid and whether it conforms to the YANG model that describes it. To access data in the YANG model, to edit it or just get the data, we need a way to specify what data we want to access. As described in the YANG [RFC](https://tools.ietf.org/html/rfc7950#section-6.4), YANG relies on XML Path Language (XPath) to specify references to various parts of the data. Sysrepo also uses XPaths to refer to data. XPath use is supported by the libyang library which Sysrepo uses to work with YANG data.

### Sysrepo and NETCONF
The other series of RFCs that Sysrepo is based on are about NETCONF. While YANG is concerned with describing the data stored in the datastore, NETCONF is the protocol that describes how the configuration of network devices is installed, modified and deleted. Sysrepo is currently integrated with the Netopeer2 NETCONF server, so applications that use sysrepo can be managed via NETCONF. Therefore, developing a Sysrepo plugin will require working with Sysrepo itself, [libyang](https://github.com/CESNET/libyang), which is the YANG library used, written in C, [Netopeer2](https://github.com/CESNET/Netopeer2) which provides a NETCONF server and client and uses [libnetconf2](https://github.com/CESNET/libnetconf2). All of these projects are written in C. While developing plugins it is preferrable to use the latest stable versions of the projects. For sysrepo, older versions like 0.7 are legacy and shouldn’t be used. The current versions of the projects are available on the corresponding GitHub pages.

The next three sections will provide high level overviews of the YANG language, XPath, and NETCONF, followed by further explanations of what a Sysrepo plugin does and how it works internally.

## The YANG language
The main purpose of the YANG language is to describe the configuration and state of a system we are managing. YANG and NETCONF were developed as part of a series of RFCs developed by the IETF to make management of network devices easier, and provide a unified way of management. Previously, to manage a network device, various vendor specific tools were used. When working with OpenWrt UCI, procd scripts and ubus were the main tools to manage systems. CISCO devices use their own tools, Juniper another set of tools, and so on. 

The IETF has already defined various YANG models for various purposes, for example for [interface management](https://tools.ietf.org/html/rfc8343). These are published as RFCs and are meant to be platform and vendor independent and standardize the management of the target systems. Other standard bodies and vendors like the ITU and OpenConfig are also working on open YANG models. A convenient way to look at all the published YANG models is the [YANG catalog](https://www.yangcatalog.org/). The project has a search frontend that allows search through the content of the catalog, a YANG validator that validates YANG modules and various other tools useful for working with YANG. The catalog is based on a GitHub repository that tracks YANG models, available [here](https://github.com/YangModels/yang). Of course, anyone can develop and use their own YANG models. 

### YANG basic syntax
Like most programming languages, YANG defines various primitive data types like integers and strings, and data structures like lists and containers. It supports importing of other modules, and separation of a single module into submodules, which can then be included by the main module. Referencing the DHCP module again, we can see that it imports two modules, as shown below:

```
import ietf-inet-types {
    prefix inet;
}

import ietf-yang-types {
    prefix yang;
}
…
leaf aftr_v4_local {
    type inet:ipv4-address-no-zone;
}

```

Imported modules are referred to using a prefix, as can be seen in the `aftr_v4_local` leaf, which has a type that is defined in the `ietf-inet-types` module. Include works the same way, except it includes submodules of a module. YANG models the data that it describes in a tree, where each node has a name and a value or child nodes. One of the simplest types is the `leaf` node, which contains a single typed value. Other commonly used types are `containers`, which are used to group related nodes into a subtree. They have no value and only contain child nodes. The concept is similar to structs in C based languages. Nodes of type `leaf-list` define a list of values of the same type. The example below shows an example of containers and leaf-lists being used in the DHCP plugin model.

```
container domains {
    leaf-list domain {
        type string;
    }
}
```

Lists define a sequence of nodes grouped and identified by the value of their key node. A list may have multiple key leafs. An example is shown in the next example.

```
list device {
    key “name”;
    leaf name {
        type string;
    }

    leaf type {
        type string;
    }
}
```

The node that is specified as the key obviously has to exist in the list.

YANG allows data models to describe constraints for the data, for example to restrict the set of valid values a node value can take. The first YANG example shows such a constraint. The statement `must “. >= ../start”;` constraints the values of the `stop` node so that they must be larger or equal to the previously defined `start` node values.

Modules can define their own types by using the `typedef` keyword. The next example shown below, demonstrates an example from the DHCP plugin model. The `enum` type works similarly to enums in C like languages.

```
typedef server-state {
    type enumeration {
        enum “server” {
            description “enable the server”;
        }
        enum “relay” {
            description “relay the server”;
        }
        enum “disabled” {
            description “disable the server”;
        }          
    }
}
```

A custom defined type has to be based on an existing type, but can further constrain the range of values it can contain.

As mentioned at the start, one of the first important things to understand here is that a YANG model describes the configuration and state data, but does not contain the actual configuration data. The configuration data is stored in another format, like XML or JSON. Configuration data most often contains actual data from the system's configuration, like the DHCP address range, interface on which the DHCP client is working and so on. State data is often read-only data such as status information, for example the state of an interface, or statistics like the number of dropped packets on an interface. State data in YANG modules is determined by the `config false;` statement. The DHCP plugin model has two containers which contain only state data, `dhcp-v4-leases` and `dhcp-v6-leases` which contain information about active DHCP leases for IPv4 and IPv6.

This covers all the types used in the DHCP YANG model. There are some other commonly used YANG types like groupings, which define a set of reusable nodes. Without being used, unlike a container, a grouping does not add nodes to the data tree. Another difference between groupings and containers is that groupings can be used at other places and refined. For example, a container might use a grouping and then refine one of the previously defined nodes. Groupings are refined with the `refine` keyword. A similar feature of the language is the ability to augment existing data models, with the `augment` keyword. It allows a module to insert additional nodes into a data model, either it’s own or another model. Both groupings and augmentation are especially useful when working with external modules. For example, a user could take an existing standardized module and then write their own module which imports and then extends the existing module so that it is tailored to their own use case.

### RPC and notifications

Other than state and configuration data, YANG also supports RPCs and notifications. RPCs (Remote Procedure Calls) are used to describe operations that the system being described supports. The operation's inputs and outputs are all described with YANG. A simplified example from the [generic-sd-bus-plugin](https://github.com/sartura/generic-sd-bus-plugin) is shown below.

```
rpc sd-bus-call {
    input {
        list sd-bus-message {
            key “sd-bus sd-bus-service”;
            leaf sd-bus {
                description “sd-bus bus to contact.”;
                mandatory true;
                type enumeration {
                    enum SYSTEM;
                    enum USER;
                }
            }
            leaf sd-bus-method {
                description “sd-bus method name.”;
                mandatory true;
                type string;
            }
            leaf sd-bus-arguments {
                description “sd-bus method arguments.”;
                mandatory true;
                type string;
            }
        }
    }
}
```

The example shows the input section of a RPC statement that defines a call to Systemd sd-bus. The outputs section looks similar.

The notification statement is similar and it is used to model notifications which are basically events, and are based on NETCONF notifications. For more information it is recommended to read the [YANG 1.1. RFC](https://tools.ietf.org/html/rfc7950).

## XPath query language

### What is XPath?

XPath is a language made to address data from an XML document. It works with an abstract tree based representation of XML. As NETCONF uses XML to encode its data, it is unsurprising that XPath is an important part of Sysrepo and YANG. It also provides functionality to test and manipulate the addressed data in basic ways. As the name implies, it uses a path based notation to address elements. Multiple XPath versions exist, 3.0 being the latest. Sysrepo however uses the 1.0 version, so that will be described here. Most of the XPath handling is done by libyang. 

### XPath in Sysrepo plugins

While working on Sysrepo plugin development there are three places where XPaths are likely to be encountered. First, when developing or working with existing YANG models. YANG uses XPaths in various language statements like `must` and `when`, while other statements like `augment` and `leafref` use a simplified subset of the XPath language. One such example was previously shown in the first YANG example, where the `must` statement uses an XPath to refer to the start node from the stop node. A simplified version of XPath can be used to access nodes in the YANG schema. When working with YANG data however, a nearly complete subset of the XPath language can be used. The second use of XPaths will be when working with libyang and Sysrepo APIs which use XPath. Lastly, the `sysrepocfg` tool which is used to import, edit and export configurations in Sysrepo often requires or benefits from XPath use.

XPath has four main types which can be returned as results of an XPath expression being evaluated. First are various types of nodes, followed by booleans, floating point numbers and strings. Expressions are evaluated in respect to a context. A context consists of many things, including a context node, a function library and a set of namespace declarations. There are some other elements, but for the purpose of Sysrepo plugin development those aren’t as important. The function library consists of functions which receive arguments of the four types previously mentioned, and return a result. For the purposes of working with YANG, the set of namespaces is the set of modules that are in use. The module prefixes correspond to XML namespace URIs in this case. The function library and set of namespace remain the same for expression and subexpression evaluation. However the context node can often change. The context node is usually the node from which the expression is being evaluated. Similarly to other path notations, `/` selects the root of the tree. Again, similarly to other path notations, there are two kinds of paths in XPath, relative and absolute. Relative paths are evaluated starting from the context node, while absolute paths start with a `/`, and are evaluated from the tree root. Paths are evaluated in steps, and every step can specify either a further subset of paths, or further filter the set of returned nodes by type or through the use of predicates. Predicates use arbitrary expressions to further filter the set of nodes. Common shortcuts like `*` to select all nodes, `..` to select a parent, `.` to select the current node and others are available.

Practical examples of XPath use will be shown together with demonstrations of the `sysrepocfg` tool in a later section of the document. For more details about XPaths see the official [XPath standard](https://www.w3.org/TR/1999/REC-xpath-19991116/).

It is important to keep in mind when working with XPaths and YANG, that the subset of the YANG model tree that can be accessed depends on where the statement with the XPath expression is defined. For example, if a `must` expression is defined in a substatement in a configuration node, the tree subset that can be accessed includes all the configuration nodes. An expression in a state node can access all configuration and state nodes. Additional rules for XPath expressions in notifications and RPCs are also described in the YANG RFC.


## NETCONF

### What is NETCONF?

[NETCONF](https://tools.ietf.org/html/rfc6241) is the protocol defined by IETF used to install, manipulate and delete configuration data on network devices. NETCONF messages are encoded in XML. The protocol communication is realized as a series of RPCs. It is based on a server-client communication model. The server is usually referred to as the agent, and the client as the manager. The server is most often running on a network device that is being managed by the client. Conceptually, NETCONF can be divided into four layers. The first is a secure transport layer, with common implementations using SSH or TLS. The next layer defines the set of possible messages that can be transferred by the NETCONF protocol including RPCs, RPC errors and responses and notifications. The messaging layer enables the next layer, the operation layer, which contains specific operations like `<get-config>`, `<edit-config>`, `<delete-config>`, `<close-session>` and others. As the names of the operations imply, they are primarily used for configuration and session management. A session is opened when a client connects to a server. Last is the content layer which isn’t described by the NETCONF RFC, and in practice it contains YANG data. The set of supported operations can be extended by the use of capabilities. The server and client then keep track of which non-standard capabilities they support, so that once they start communicating they can negotiate and find out which capabilities they have in common. Similarly to YANG, NETCONF also makes a distinction between state and config data. The `get-config` command gets only the configuration data, while the `get` command gets both. The NETCONF protocol defines the existence of at least one, and most often multiple configuration datastores. The three most common datastores are `startup`, `running` and `candidate`. The RFC defines a configuration datastore as “a complete set of configuration data that is required to get the device from its initial default state into a desired operational state”. The only datastore that the RFC requires to be present on all NETCONF servers is the running datastore. It contains the currently active configuration on the network device. The candidate datastore can be manipulated without affecting the running configuration and can then be committed to the running datastore, when the changes are finished. The startup datastore holds the initial configuration data that is loaded onto the device during the boot process. Sysrepo uses all three datastores, with some changes. As datastores for network management are a more general concept, most of the definitions are actually in the [NMDA](https://tools.ietf.org/html/rfc8342) (Network Management Datastore Architecture) RFC. The RFC defines a general architectural model that is not necessarily tied to NETCONF, although most NETCONF servers follow it.

## Sysrepo plugin architecture

### What are Sysrepo plugins?

There are two main approaches to using Sysrepo itself and developing applications that use it: a **direct** and **indirect** approach. The direct approach involves calling Sysrepo functions from the application itself whenever configuration data are needed or executing specific callbacks to react to configuration changes. The indirect approach implies writing a stand-alone daemon that will translate Sysrepo calls to actions specific for the application. This indirect approach is usually simpler to employ for existing applications because then they do not need to be changed themselves to utilize the Sysrepo datastore at the cost of having an additional intermediary process (daemon). Both of these approaches are visualized on the image below.

![sysrepo plugin approaches](https://github.com/sysrepo/sysrepo/raw/devel/doc/sr_apps.png)

If there are several daemons written in the indirect approach, they can be written as plugins and then all managed by one process, for example the `sysrepo-plugind` daemon. This daemon is a simple daemon that groups all available Sysrepo plugins into a single process. 

### Initialization and connecting to Sysrepo

Given that Sysrepo applications can be written in the form of a plugin — the indirect approach, or in the form of a daemon — the direct approach, it may be prudent if possible to write such applications to support both approaches. Sysrepo plugins via the indirect approach are initialized from the `sysrepo-plugind` daemon by exposing both `sr_plugin_init_cb` and `sr_plugin_cleanup_cb` functions. However, by calling those functions as part of the application’s main entrance function it is possible to run the code as a daemon. For example, a snippet of the [DHCP plugin](https://github.com/sartura/dhcp/tree/devel) initialization code is shown below.

```
int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
    (...)
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data)
{
    (...)
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

int main()
{
    (...)

    error = sr_plugin_init_cb(session, &private_data);
    if (error)
   	 goto out;

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
   	 sleep(1); /* or do some more useful work... */
    }

out:
    sr_plugin_cleanup_cb(session, private_data);
    sr_disconnect(connection);

    return error ? -1 : 0;
}

(...)

#endif
```

From the initialization code above, it can be seen that there is an `#ifndef PLUGIN` guard which allows the plugin to either be loaded as a plugin, or run as a daemon application. This define guard is determined during build-time via the respective build system flag option. In this particular example, the CMake build system is used which allows passing flags such as `-DPLUGIN=TRUE`. The aforementioned variable will build the respective code as a shared object file i.e. plugin for `sysrepo-plugind`. Likewise, when `-DPLUGIN=FALSE` the build system output will consist of a single binary which can be executed directly.

Applications that use Sysrepo, or plugins themselves interface with the Sysrepo database through certain initialization steps. An application written using the direct approach must first connect to Sysrepo using the `sr_connect` API call. This connection is expected to be unique per application and usually lasts until the program ends, although it is possible to have multiple connections per application. After successful connection to Sysrepo, an application should also start a session by invoking the `sr_session_start` API function using the provided connection. An arbitrary number of these sessions can be created. Most importantly, the threading model needs to be considered when using this API. There are no inherent restrictions in Sysrepo regarding sessions because every session requires only little resources, and having many of them should not cause any problems. A session must be initialized by selecting the appropriate Sysrepo datastore.

### Sysrepo datastores

Sysrepo does not implement the whole NMDA RFC. It fully supports `startup`, `running`, `candidate` and `operational` datastores. The `startup`, `running` and `candidate` datastores work as described in the NETCONF section. The `operational` datastore corresponds to parts of the `running` datastore with the addition of state data. It is read-only. It is empty by default, and the data added to it is either operational data or data resulting from a subscription.

### Connecting to Sysrepo datastores
As previously mentioned, the Sysrepo `sr_session_start` API call requires users to select which datastore the user wants to connect to. When an application is written using the direct approach the code show below might be used when a user connects to the `running` datastore:

```
int main()
{
    int error = SR_ERR_OK;
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    void *private_data = NULL;
   
    /* connect to sysrepo */
    error = sr_connect(SR_CONN_DEFAULT, &connection);
    if (error)
   	 goto out;


    error = sr_session_start(connection, SR_DS_RUNNING, &session);
    if (error)
   	 goto out;


    error = sr_plugin_init_cb(session, &private_data);
    if (error)
   	 goto out;

    (...)

out:
    sr_plugin_cleanup_cb(session, private_data);
    sr_disconnect(connection);

    return error ? -1 : 0;
}
```

The implementation of the `sr_plugin_init_cb` function is the same for either direct or indirect approach. When a Sysrepo plugin is initialized, the managing daemon should pass the appropriate session context. From this session any additional sessions can be created by fetching the connection using `sr_session_get_connection` and creating sessions on top of that using the usual `sr_session_start` API. An example of such a process is shown below.

```
int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
    int error = 0;
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *startup_session = NULL;
    sr_subscription_ctx_t *subscription = NULL;

    *private_data = NULL;

    connection = sr_session_get_connection(session);
    error = sr_session_start(connection, SR_DS_STARTUP, &startup_session);
    if (error)
   	 goto out;

    *private_data = startup_session;

    if (running_datastore_is_empty == true) {
   	 // do something e.g.
   	 // sr_copy_config(startup_session, DHCP_YANG_MODEL, SR_DS_RUNNING, 0, 0);
    }

out:
    return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}
```

From the provided code above, it can be seen that the newly created session is attached to the `startup` datastore i.e. it has been invoked with `SR_DS_STARTUP`.

### Sysrepo subscriptions
After a connection and the required sessions were established, the next step a sysrepo plugin will usually contain is subscription to various parts of the YANG model it works with. There are four types of subscriptions, and four matching function calls. One for changes in the configuration part of the model, one for RPCs, one for notifications and the last one for state data. When a subscription is made, a callback function is registered. That callback function is then called when a change happens. Subscriptions are usually registered during plugin initialization.

#### Module change subscriptions
The function used to subscribe to configuration changes is `sr_module_change_subscribe`. An example of its use is shown below.

```
SRP_LOG_INFMSG("subscribing to module change");

error = sr_module_change_subscribe(session, DHCP_YANG_MODEL, "/" DHCP_YANG_MODEL ":*//*", dhcp_module_change_cb, *private_data, 0, SR_SUBSCR_DEFAULT, &subscription);

if (error) {
	SRP_LOG_ERR("sr_module_change_subscribe error (%d): %s", error, sr_strerror(error));
	goto error_out;
}
```

The first argument is the previously initialized session, followed by the model, which in this case is `terastream-dhcp`. The third argument is the XPath that specifies what part of the data model should be tracked for changes, which in this case is the whole model. Following that is the callback that will be called when a change occurs. The next argument is priority, which determines the order in which callbacks will be called for the same module. Since this case has only a single callback, the value is 0. Lastly, there are the subscription options, and the subscription context. The subscription options used here are set to the default `SR_SUBSCR_DEFAULT` value. Subscription options enable various things, like reuse of a single subscription context for multiple subscriptions, whether `SR_EV_UPDATE` events will be received, and so on.


The registered subscription callback is called with an event when a change occurs. By default there are two events, although there can be more. The two default events are `SR_EV_CHANGE`, which occurs the first time the changes appear, and `SR_EV_DONE` which appears when the changes have been committed. Another event is `SR_EV_ABORTED`. An example of event handling is shown below.

```
if (event == SR_EV_ABORT) {
		SRP_LOG_ERR("aborting changes for: %s", xpath);
		error = -1;
		goto error_out;
	}

	if (event == SR_EV_DONE) {
		error = sr_copy_config(startup_session, DHCP_YANG_MODEL, SR_DS_RUNNING, 0, 0);
		if (error) {
			SRP_LOG_ERR("sr_copy_config error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
	}

	if (event == SR_EV_CHANGE) {
		error = sr_get_changes_iter(session, xpath, &dhcp_server_change_iter);
		if (error) {
			SRP_LOG_ERR("sr_get_changes_iter error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
...
...
```

As we can see, the callback need to check which type of event it has received and then handle the event. If `SR_EV_CHANGE` is received, that means that the changes have just arrived, so they are parsed and handled appropriately. If `SR_EV_DONE` is received, then the changes have already been committed, so they are copied from the running datastore into the startup datastore in this case. The `startup_session` session was previously initialized to work with the startup datastore.

#### Operational subscriptions

Operational subscriptions are used to provide data when a client requests it. They work with the operational datastore. To register operational subscriptions the `sr_oper_get_items_subscribe` function is used. An example from the DHCP plugin is shown below.

```
SRP_LOG_INFMSG("subscribing to get oper items");

	error = sr_oper_get_items_subscribe(session, DHCP_YANG_MODEL, DHCP_V4_STATE_DATA_PATH, dhcp_state_data_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	error = sr_oper_get_items_subscribe(session, DHCP_YANG_MODEL, DHCP_V6_STATE_DATA_PATH, dhcp_state_data_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}
```

The function signature is similar to the module change subscription function. The first argument is again the session, followed by the model, XPath, callback function, private data, subscription options and subscription context. As we can see, the module change subscription context is being reused here. The start of the callback is shown below.

```
	static int dhcp_state_data_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
	srpo_ubus_result_values_t *values = NULL;
	srpo_ubus_call_data_t ubus_call_data = {.lookup_path = NULL, .method = NULL, .transform_data_cb = NULL};
	int error = SRPO_UBUS_ERR_OK;


            if (!strcmp(path, DHCP_V4_STATE_DATA_PATH) || !strcmp(path, "*")) {
		srpo_ubus_init_result_values(&values);

		ubus_call_data = (srpo_ubus_call_data_t){.lookup_path = "router.network", .method = "leases", .transform_data_cb = dhcp_v4_ubus, .timeout = 0, .json_call_arguments = NULL};
		error = srpo_ubus_call(values, &ubus_call_data);
		if (error != SRPO_UBUS_ERR_OK) {
			SRP_LOG_ERR("srpo_ubus_call error (%d): %s", error, srpo_ubus_error_description_get(error));
			goto out;
		}

		error = store_ubus_values_to_datastore(session, request_xpath, values, parent);
		if (error) {
			SRP_LOG_ERR("store_ubus_values_to_datastore error (%d)", error);
			goto out;
		}

		srpo_ubus_free_result_values(values);
		values = NULL;
	}

	if (!strcmp(path, DHCP_V6_STATE_DATA_PATH) || !strcmp(path, "*")) {
		srpo_ubus_init_result_values(&values);
```


As the previous two examples show, there are two separate cases being handled here. One case handles the DHCPv6 state data, and the other the DHCPv4 state data. The separation is needed as the callback needs to provide and process different state data for the two different DHCP versions.

Subscriptions for RPCs and notifications work in a similar manner. The RPC subscription registration function is `sr_rpc_subscribe_tree`. The RPC callback receives RPC inputs, and should then call the RPC and fill the output libyang tree. An example is available in the [generic-sd-bus-plugin](https://github.com/sartura/generic-sd-bus-plugin). The variant without the tree postfix shouldn’t be used, as it only exists for legacy reasons.

## Sysrepo Utilities

This section describes various utility tools that make working with Sysrepo plugins, Sysrepo and YANG easier.

### Sysrepoctl

The primary purpose of sysrepoctl is to enable modification of YANG modules. It can list, install, remove and change various properties of YANG modules on a system. 

To list the YANG modules on a system, the `sysrepoctl -l` command can be used. Example results are shown below.

```
root@35c61c6ef93a:/# sysrepoctl -l
Sysrepo repository: /opt/dev/sysrepo/build/repository

Module Name                | Revision   | Flags | Owner     | Permissions | Submodules | Features
-------------------------------------------------------------------------------------------------
ietf-datastores            | 2018-02-14 | I     | root:root | 666         |            |
ietf-inet-types            | 2013-07-15 | i     |           |             |            |
ietf-netconf               | 2011-06-01 | I     | root:root | 666         |            |
ietf-netconf-notifications | 2012-02-06 | I     | root:root | 666         |            |
ietf-netconf-with-defaults | 2011-06-01 | I     | root:root | 666         |            |
ietf-origin                | 2018-02-14 | I     | root:root | 666         |            |
ietf-yang-library          | 2019-01-04 | I     | root:root | 666         |            |
ietf-yang-metadata         | 2016-08-05 | i     |           |             |            |
ietf-yang-types            | 2013-07-15 | i     |           |             |            |
sysrepo-monitoring         | 2020-04-17 | I     | root:root | 600         |            |
yang                       | 2017-02-20 | I     | root:root | 666         |            |

Flags meaning: I - Installed/i - Imported; R - Replay support; N - New/X - Removed/U - Updated; F - Feature changes
```

To install a module, for example the terastream-dhcp YANG module that is required by the DHCP plugin `sysrepoctl -i ./terastream-dhcp\@2017-12-07.yang` should be used. The results of listing the modules on the system again are shown below.

```
root@35c61c6ef93a:/# sysrepoctl -l
Sysrepo repository: /opt/dev/sysrepo/build/repository

Module Name                | Revision   | Flags | Owner     | Permissions | Submodules | Features
-------------------------------------------------------------------------------------------------
ietf-datastores            | 2018-02-14 | I     | root:root | 666         |            |
ietf-inet-types            | 2013-07-15 | i     |           |             |            |
ietf-netconf               | 2011-06-01 | I     | root:root | 666         |            |
ietf-netconf-notifications | 2012-02-06 | I     | root:root | 666         |            |
ietf-netconf-with-defaults | 2011-06-01 | I     | root:root | 666         |            |
ietf-origin                | 2018-02-14 | I     | root:root | 666         |            |
ietf-yang-library          | 2019-01-04 | I     | root:root | 666         |            |
ietf-yang-metadata         | 2016-08-05 | i     |           |             |            |
ietf-yang-types            | 2013-07-15 | i     |           |             |            |
sysrepo-monitoring         | 2020-04-17 | I     | root:root | 600         |            |
terastream-dhcp            | 2017-12-07 | I     | root:root | 600         |            |
yang                       | 2017-02-20 | I     | root:root | 666         |            |

Flags meaning: I - Installed/i - Imported; R - Replay support; N - New/X - Removed/U - Updated; F - Feature changes
```

To remove a module, for example the same terastream-dhcp module, the `-u` flag should be used, like this: `sysrepoctl -u terastream-dhcp`. However, this time the argument is the module name, not the path used during installation. 

Additional flags are available, for example the `-c` flag changes various module properties. The snabb plugin’s ietf-softwire-br model needs to have binding-mode enabled for the example. To achieve that, the following command can be used `sysrepoctl -c ietf-softwire-br -e binding-mode`. After that command, the `Features` column in `sysrepoctl list` output should show `binding-mode` as a new feature of `ietf-softwire-br`. If a module imports another module, the imported module has to be installed first. For example, installing `ieft-softwire-br` without the `ietf-softwire-common` module being present will result in the error shown below.

```
root@ea332ef1c813:/opt/dev# sysrepoctl -i snabb/src/lib/yang/ietf-softwire-br.yang
[ERR]: Data model "ietf-softwire-common" not found.
[ERR]: Importing "ietf-softwire-common" module into "ietf-softwire-br" failed.
[ERR]: Module "ietf-softwire-br" parsing failed.
sysrepoctl error: Failed to install module "snabb/src/lib/yang/ietf-softwire-br.yang" (libyang error)
```

More information about the sysrepoctl command is available by running `sysrepoctl -h` and in the [official documentation](https://netopeer.liberouter.org/doc/sysrepo/master/sysrepoctl.html). 

### Sysrepocfg

The sysrepocfg tool allows manipulation of configuration data in Sysrepo. It supports importing, exporting and modification of data for a specific datastore and model. It can also be used to send notifications and RPCs. An example command which exports the configuration is shown below. The `-X` flag tells sysrepocfg to export the configuration to stdout. The `-d` flag selects the datastore, which will be `startup` in this example. The `-f` flag selects the format of the configuration output, either XML or JSON. Finally, we can select a model with `-m`.

```
$ sysrepocfg -X -d startup -f json -m 'terastream-wireless'
{
  "terastream-wireless:apsteering": {
    "enabled": false
  },
  "terastream-wireless:bandsteering": {
    "enabled": false,
    "policy": false
  },
  "terastream-wireless:devices": {
    "device": [
      {
        "name": "wl0",
        "type": "broadcom",
        "country": "EU/13",
        "frequencyband": "5",
        "bandwidth": 80,
        "hwmode": "auto",
        "channel": "auto",
        "scantimer": 15,
        "wmm": true,
        "wmm_noack": false,
        "wmm_apsd": true,
        "txpower": 100,
        "rateset": "default",
        "frag": 2346,
        "rts": 2347,
        "dtim_period": 1,
        "beacon_int": 100,
        "rxchainps": false,
        "rxchainps_qt": 10,
        "rxchainps_pps": 10,
        "rifs": false,
        "rifs_advert": false,
        "maxassoc": 32,
        "beamforming": true,
        "doth": 1,
        "dfsc": true,
        "interface": [
          {
            "name": "cfg043579",
            "network": "lan",
            "mode": "ap",
            "ssid": "PANTERA-7858",
            "encryption": "psk2",
            "cipher": "auto",
            "key": "keykeykey",
            "gtk_rekey": 3600,
            "macfilter": 0,
            "wps_pbc": true,
            "wmf_bss_enable": true,
            "bss_max": 32,
            "ifname": "wl0"
          }
        ]
      },
      {
        "name": "wl1",
        "type": "broadcom",
        "country": "EU/13",
        "frequencyband": "2.4",
        "bandwidth": 20,
        "hwmode": "auto",
        "channel": "auto",
        "scantimer": 15,
        "wmm": true,
        "wmm_noack": false,
        "wmm_apsd": true,
        "txpower": 100,
        "rateset": "default",
        "frag": 2346,
        "rts": 2347,
        "dtim_period": 1,
        "beacon_int": 100,
        "rxchainps": false,
        "rxchainps_qt": 10,
        "rxchainps_pps": 10,
        "rifs": false,
        "rifs_advert": false,
        "maxassoc": 32,
        "doth": 0,
        "interface": [
          {
            "name": "cfg063579",
            "network": "lan",
            "mode": "ap",
            "ssid": "PANTERA-7858",
            "encryption": "psk2",
            "cipher": "auto",
            "key": "rootrootroot",
            "gtk_rekey": 3600,
            "macfilter": 0,
            "wps_pbc": true,
            "wmf_bss_enable": true,
            "bss_max": 32,
            "ifname": "wl1"
          }
        ]
      }
    ]
  }
}
```


Configurations can be edited by using the `-E` flag, and imported with the `-I` flag. Instead of exporting, importing or editing the whole configuration file, a subset of the tree can be edited by specifying an xpath to the subset of the tree with the `-x` flag. An example is shown below.

```
$ sysrepocfg -X -d operational -f json -x '/terastream-wireless:devices-state'
{
  "terastream-wireless:devices-state": {
    "device": [
      {
        "name": "wl0",
        "channel": "100",
        "ssid": "PANTERA-7666",
        "encryption": "psk2",
        "up": true
      }
    ]
  }
}
```


Additional information is available by running sysrepocfg with the `-h` help flag, and in the [official documentation](https://netopeer.liberouter.org/doc/sysrepo/master/sysrepocfg.html).
