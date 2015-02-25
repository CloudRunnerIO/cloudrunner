#!/bin/bash

set -e
set -b
# set -x # DEBUG

# Variables

PROJECT_NAME=cloudrunner

VER_PAT=$(./scripts/rpm/getrev.sh | cut -d "." -f 1-3 )
BRANCH=$(./scripts/rpm/getrev.sh | cut -d "." -f 4 )

#VER_PAT="$(./scripts/rpm/getrev.sh)"
#VER_PAT=0.1
#BRANCH="$(./scripts/rpm/getbranch.sh)"
DIRNAME="$PROJECT_NAME-$VER_PAT.$BRANCH"

if [ "$#" != 0 ]; then
    BUILD_RELEASE="$1"
else
    echo "No build arch specified (epel-5-x86_64, epel-6-x86_64, fedora-19-x86_64, ...)! "
    exit 2
fi

echo
echo "Building "$PROJECT_NAME":"
echo -e "\tBranch:   [$BRANCH]"
echo -e "\tRevision: [$VER_PAT]"
echo

echo "Starting build"
rm -rf build/"$DIRNAME"/
mkdir -p build/"$DIRNAME"/
mkdir -p rpms

cp dist/"$PROJECT_NAME"*.tar.gz build/"$DIRNAME"/
cp "$PROJECT_NAME".spec build/"$DIRNAME"/"$PROJECT_NAME".spec

echo "Building "$PROJECT_NAME" for $BUILD_RELEASE"
mock -r $BUILD_RELEASE --buildsrpm --sources build/"$DIRNAME"/ --spec "build/$DIRNAME/"$PROJECT_NAME".spec" --resultdir="build/$DIRNAME/output/" # --no-cleanup-after

mock -r $BUILD_RELEASE --rebuild build/"$DIRNAME"/output/*.src.rpm --resultdir=build/"$DIRNAME"/rpms/

rm -rf build/"$DIRNAME"/rpms/*.src.rpm

mv build/"$DIRNAME"/rpms/*.rpm "rpms"

rm -rf build/"$DIRNAME"/

echo
echo 'RPM Packages built OK!'
