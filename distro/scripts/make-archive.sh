#!/usr/bin/env bash
# create archive from current source using git

VERSION=$(grep \(SYSREPO_M.*_VERSION CMakeLists.txt | sed 'N; N; s/[[:print:]]*[[:blank:]]\([[:digit:]]\+\)[[:print:]]/\1/g; s/\n/./g')

NAMEVER=sysrepo-$VERSION
ARCHIVE=$NAMEVER.tar.gz

git archive --format tgz --output $ARCHIVE --prefix $NAMEVER/ HEAD
mkdir -p pkg/archives/dev/
mv $ARCHIVE pkg/archives/dev/

# apkg expects stdout to list archive files
echo pkg/archives/dev/$ARCHIVE
