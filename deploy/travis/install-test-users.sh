#!/bin/sh
set -e


useradd -M sysrepo-user1
useradd -M sysrepo-user2
useradd -M sysrepo-user3

groupadd sysrepo-users

usermod -a -G sysrepo-users sysrepo-user1
usermod -a -G sysrepo-users sysrepo-user2
usermod -a -G sysrepo-users sysrepo-user3

chmod g+rw,o-rw repository/data/*
chown :sysrepo-users repository/data/*

