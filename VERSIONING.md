# sysrepo Project Versioning

Versions consist of a three numbers in the form of MAJOR.MINOR.MICRO. The
numbers are non-negative integers changed incrementally (1.9.0 -> 1.10.0). The
numbers do not contain leading zeroes.

A change in the MICRO number is an internal change, in the most cases a bugfix,
or a set of internal changes. Such a change:
- does not change API/ABI of any library provided by sysrepo project,
- does not add any new functionality,
- does not affect any option of the sysrepo command line tools.

Meanings of the MINOR number slightly differs according to the MAJOR number
value. If the MAJOR is zero, the MINOR number changes may include actually any
change, including
- API/ABI of the sysrepo libraries,
- options or functions of the command line tools.

When the MAJOR number is zero, the MINOR number changes have actually the
menaings of the MAJOR number change. In the case of libraries, it means that
also the libraries' SONAME is set to libname.so.0.MINOR.

When the MAJOR number is not equal to zero, the MINOR number change:
- does not change libraries' API/ABI nor the tools' options meaning
- can add new functionality (in API or in command line tools or daemons)
- is backward compatible
- does not change the libraries' SONAME value

Note that these rules are not applied strictly when the release is in a beta
stage (i.e. the changes are placed in the devel branch). Therefore, e.g.
libraries' SONAMEs may not solve the compatibility issues when installed from
the devel branch (API/ABI of the libraries with the same SONAME can differ).

On the other hand, when the changes are applied to the master branch, the
content of the particular version must not change. It means that each
merge to the master branch includes the change of the version.

## Versioning Process

All the changes are supposed to be implemented in the separated branches and
merged into the sysrepo `devel` branch via pull requests. The pull request
author is supposed to provide enough information about the change for the
versioning purposes. The project maintainer who merges the pull request is
responsible to decide if and how the version number will be changed according
to the above rules.

Note that multiple pull requests can result just in a single change of the
version number. However, it is expected that such a change is caused by the
first merged pull request (to avoid collision with the previous version
possibly present in the master branch).

Version numbers are taken from the CMakeList.txt file. The change of these
numbers is expected in a separated commit with the following commit message:
```
Bump version to MAJOR.MINOR.MICRO
```

