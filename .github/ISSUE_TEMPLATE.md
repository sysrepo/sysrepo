### How to submit issue
Please use this text as a template and replace text in the sections or remove
the entire section if that does not apply to your issue. For example in case of
question or feature request, just description with some example is probably
fine. Also remember to use github's markup form properly, especially in case of
output or code listing.

### Things you may try first
(put "x" in "[]" if you already tried following)
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

Thanks!
