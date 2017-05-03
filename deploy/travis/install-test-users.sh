#!/bin/sh
set -e

# create new users for testing purposes
useradd -M sysrepo-user1
useradd -M sysrepo-user2
useradd -M sysrepo-user3
useradd -M sysrepo-user4

# create group sysrepo-users and make all newly created users members of it
groupadd sysrepo-users
usermod -a -G sysrepo-users sysrepo-user1
usermod -a -G sysrepo-users sysrepo-user2
usermod -a -G sysrepo-users sysrepo-user3
usermod -a -G sysrepo-users sysrepo-user4

# permissions for data files
chmod o+x /home
chmod o+x /home/travis
chmod g+rw,o-rw repository/data/*

# change group to sysrepo-users for all data files
chgrp sysrepo-users repository/data/*
chgrp sysrepo-users repository/data

# access rights for newly created data files
chmod g+ws repository/data
setfacl -d -m g::rw repository/data
setfacl -d -m o::0 repository/data
