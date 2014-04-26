mychroot="wheezy-chroot"
#PROJECT_NAME=cloudrunner
PROJECT_NAME=$(basename $PWD)

VER=$(cat version.py |sed -e "s|'||g" | cut -d" " -f 3)

pushd ..
mkdir $mychroot/
cp  -a cloudrunner $mychroot/cloudrunner-$VER

sudo debootstrap squeeze $mychroot http://http.debian.net/debian/
rm -rf $mychroot/cloudrunner/.git

#exit 0

sudo chroot $mychroot <<EOF
set -e
apt-get update
apt-get install\
        cmake\
        gcc g++\
        libx11-dev libxtst-dev\
        libpcre3-dev\
        libavahi-common-dev libavahi-client-dev\
        libconfig++8-dev\
        libgtk2.0-dev \
        libxmu-dev libxt-dev \
        quilt swig libssl-dev \
        python-m2crypto libzmq-dev
        python-setuptools

export DEBEMAIL="ssabchew at yahoo dot com"
export DEBFULLNAME="Stiliyan Sabchew"
cd ../"$PROJECT_NAME-$VER"
tar -czf ../"$PROJECT_NAME-$VER.tar.gz" ../"$PROJECT_NAME-$VER"
echo s|dh_make -f ../"$PROJECT_NAME-$VER".tar.gz
dpkg-buildpackage -us -uc
rm -rf ../"$PROJECT_NAME-$VER"
rm -rf ../"$PROJECT_NAME-$VER".tar.gz
ls ../*.deb &>/dev/null && echo -e "\n\n=== this is your package:" ../*.deb ;echo
EOF

mkdir -p ~/dist/deb
cp cloudrunner $mychroot/cloudrunner*deb ~/dist/deb/

