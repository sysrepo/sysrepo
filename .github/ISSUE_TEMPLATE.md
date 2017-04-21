### Things you may try first 
(put "x" in "[]" if you already tried those. If you haven't - we will)
* [] Did you check if this is a duplicate issue?
* [] Did you test it on the latest sysrepo devel branch?

### Description
[Description of the bug or feature]

### Steps to Reproduce
1. [First Step]
2. [Second Step]
3. [and so on...]

**Expected behavior:**
 [What you expected to happen]

**Actual behavior:**
 [What actually happened]

### Versions
Please provide versions for software needed to reproduce the bug:
Sysrepo version: `sysrepod -v`.
libyang version: `yanglint -v`
netopeer2-server: `netopeer2-server -V` (optional)

### Attachments
Please run sysrepo daemon in debug mode and write the logs to a file. For example:
`sysrepod -d -l 4 &> sysrepod.log`.

Similarly, if Netopeer2 server is used, also provide us with its log:
`netopeer2-server -d -v3 &> netopeer2-server.log` (optional)

You're also welcomed to provide us with any other data you think may be useful.
For example:
Installed modules: `sysrepoctl -l`
Content of datastore used: check files in  Sysrepo data directory (default `/etc/sysrepo/data`).

Provide us with those attachments and keep your fingers crossed. 
Thanks!
