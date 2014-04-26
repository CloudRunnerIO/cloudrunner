#!/bin/bash

## A script to convert rpms to debian packages
##

mychroot="wheezy-chroot"
my_user=rpmmaker
locdeb_repo=~/dist/deb
remote_deb_repo=/srv/www/repo-common.bellstack.com/debian/
DST=repo.intg.cloudrunner.io
ruser=root
work=~/workspace

pushd $work
mkdir $mychroot/
if [ -d ~/dist/epel-6-x86_64/ ] ;then
sudo cp  ~/dist/epel-6-x86_64/*[src].rpm $mychroot/debuild

sudo debootstrap squeeze $mychroot http://http.debian.net/debian/

#exit 0

sudo chroot $mychroot <<EOF
set -e
apt-get update
apt-get install alien
pushd debuild
if ls rpms/*.rpm &>/dev/null ;then
    cd deb
    rm -rf *
    alien ../rpms/*
    dpkg-scanpackages . /dev/null | gzip -9c > Packages.gz
    cd ..
else
    echo "Cannot find RHEL 6 rpms.
fi
popd
EOF
sudo chown -R $myuser:  $mychroot/
mkdir -p ~/dist/deb
rsync -aH $mychroot/debuild/deb/ $deb_repo

rsync -aH $mychroot/debuild/deb/ $ruser@$DST:$remote_deb_repo
