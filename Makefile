REV := $(shell ./scripts/rpm/getrev.sh .)
# Remove - and . from branch - we cannot add them into Revision
BRANCH := $(shell ./scripts/rpm/getbranch.sh | sed 's|-|_|' | sed 's|\.||')

VERSION := $(shell ./scripts/rpm/getrev.sh | cut -d "." -f 1-3 )
RELEASE := $(shell ./scripts/rpm/getrev.sh | cut -d "." -f 4 )

SRC=src/
PY=`python -c 'import sys; print sys.version[:3]'`
__python=$(shell V=$$(python -V 2>&1 | awk '{ print $$2 }' | sed 's/\(.*\)\..*/\1/g'); if [[ "$$V" < '2.6' ]]; then echo 'python2.6'; else echo 'python$$PY'; fi)

# Default target executed when no arguments are given to make.
.PHONY : default_target
default_target: all


.PHONY: all
all: clean
	$(__python) setup.py build
        ## _last_ ## $(__python) setup.py develop --install-dir . -m


.PHONY: sdist
sdist: clean
	rm -rf dist/cloudrunner*.tar.gz
	$(__python) setup.py sdist


.PHONY: rpm
rpm: sdist
	rm -rf ~/rpmbuild/SOURCES/cloudrunner*.tar.gz
	rm -rf ~/rpmbuild/RPMS/noarch/cloudrunner*.rpm
	rm -rf ~/rpmbuild/SRPMS/cloudrunner*.src.rpm
	cp dist/cloudrunner*.tar.gz ~/rpmbuild/SOURCES/
	cp cloudrunner.spec.in cloudrunner.spec
	sed -i 's/^Release:.*/Release:        $(RELEASE)%{?dist}/g' cloudrunner.spec
	sed -i 's/^Version:.*/Version:        $(VERSION)/g' cloudrunner.spec
	rpmbuild -ba cloudrunner.spec
	rm cloudrunner.spec

.PHONY: rpm-el5_64
rpm-el5_64: sdist
	./scripts/rpm/rpm-mock.sh epel-5-x86_64

.PHONY: rpm-el6_64
rpm-el6_64: sdist
	./scripts/rpm/rpm-mock.sh epel-6-x86_64

.PHONY: rpm-f19_64
rpm-f19_64: sdist
	./scripts/rpm/rpm-mock.sh fedora-19-x86_64

.PHONY: rpm-el5_32
rpm-el5_32: sdist
	./scripts/rpm/rpm-mock.sh epel-5-i386

.PHONY: rpm-el6_32
rpm-el6_32: sdist
	./scripts/rpm/rpm-mock.sh epel-6-i386

.PHONY: rpm-f19_32
rpm-f19_32: sdist
	./scripts/rpm/rpm-mock.sh fedora-19-i386

.PHONY: userinstall
userinstall: gen_stubs
	$(__python) setup.py install --user

.PHONY: clean
clean:
	##  $(__python) setup.py develop --uninstall --install-dir . -m
	echo "Remove other temporary files..."
	rm -rf easy_install* src/*.egg-info .coverage
	rm -rf build

.PHONY: test
test:
	tox
