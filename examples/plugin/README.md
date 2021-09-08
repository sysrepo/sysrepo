## Oven Plugin

Here an example `oven` plugin configuring an oven can be found. It should provide a good hands-on tutorial
to explain all basic principles of YANG and their implementation in *sysrepo*.

It is compiled as part of the standard *sysrepo* compilation but before the plugin can be used, it must
be installed for *sysrepo-plugind* to find it. That entails simply copying the `oven.so` file into the
plugin directory, which is printed by `cmake` during the project configuration as `SRPD plugins path`.

There is full explanation of the example YANG module and instructions how to install and run the plugin in
the documentation. Once built, it can be found at a separate page `sysrepo/Developer Guide/Plugin Example`,
which is also hosted online [here](https://netopeer.liberouter.org/doc/sysrepo/master/html/example.html).
Note especially the section `Trying It Out` that is further down on the page.
