#!/bin/bash

set -e
set -b
# set -x # DEBUG

# Variables

PROJECT_NAME=cloudrunner

VER_PAT="$(./scripts/rpm/getrev.sh)"
#VER_PAT=0.1
BRANCH="$(./scripts/rpm/getbranch.sh)"
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

rm -rf ../"$DIRNAME"/
mkdir ../"$DIRNAME"/
cp dist/"$PROJECT_NAME"*.tar.gz ../"$DIRNAME"/
cp "$PROJECT_NAME".spec.in ../"$DIRNAME"/"$PROJECT_NAME".spec
sed -i "s/^Release:.*/Release:        $VER_PAT.$BRANCH.bstk%{?dist}/g" ../"$DIRNAME"/"$PROJECT_NAME".spec
#sed -i "s/^Release:.*/Release:        $BRANCH%{?dist}/g" ../"$DIRNAME"/"$PROJECT_NAME".spec

echo "Building "$PROJECT_NAME" for $BUILD_RELEASE"
mock -r $BUILD_RELEASE --buildsrpm --sources ../"$DIRNAME"/ --spec "../$DIRNAME/"$PROJECT_NAME".spec" --resultdir="../$DIRNAME/output/" # --no-cleanup-after

#mock -r $BUILD_RELEASE --no-clean --rebuild ../"$DIRNAME"/output/*.src.rpm --resultdir="$HOME/rpmbuild/RPMS/x86_64/"
mock -r $BUILD_RELEASE --rebuild ../"$DIRNAME"/output/*.src.rpm --resultdir="$HOME/dist/$BUILD_RELEASE"
if [ ! -d "$HOME/dist/SRPMS/" ] ;then 
    mkdir -p "$HOME/dist/SRPMS/" || echo Cannot create "$HOME/dist/SRPMS/"
fi
mv ../"$DIRNAME"/output/*.src.rpm "$HOME/dist/SRPMS/"
rm -rf ../"$DIRNAME"/

echo
echo 'RPM Packages built OK!'
