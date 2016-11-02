# Docker image with Sysrepo datastore

Run sysrepo tests in the container:
```
docker run -it --name sysrepo --rm sysrepo/sysrepo:latest
cd sysrepo/build/
make test
```
