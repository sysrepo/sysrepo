# upstream packaging

This directory contains upstream packaging sources in apkg format.

apkg tool can be used to build packages directly from this source repo.

See apkg docs: https://pkg.labs.nic.cz/pages/apkg/


## RPM-based system (Fedora, CentOS, SUSE, ...) quickstart

```
sudo dnf install -y git rpm-build python3-pip
pip3 install apkg

apkg build -b
```
