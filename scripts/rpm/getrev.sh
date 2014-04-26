#!/bin/bash

if [ -d .svn ]; then
    URL="$(svn info | grep '^URL: ' | cut -c 6- | tr -d ':@[](){}-')"
    echo "${URL##*/}"|sed 's/^[0-9]*.[0-9]*_//' > VERSION
elif [ -d '.git' ]; then
    if [ "$(git branch |grep "\*" |grep master )" ] ;then
        # for master branch-  will use date-commit for revision
        (( ver=$(git log --pretty=format:'%ad %h %d' --abbrev-commit --date=iso -1|awk {'print $1"_"$2"."$4'}|sed -e 's/-/_/g' | sed -e 's/\:/./g') && echo ${ver}) || echo unknown ) > `dirname $0`/../../VERSION
    else
        (ver=$(git describe --long --tags --always) && ver=${ver%%-*} ; ver2=$(git branch -r --contains $ver | grep stable |cut -d "/" -f3) ; \
        echo ${ver}.${ver2} || echo unknown) > $(dirname $0)/../../VERSION
    fi
fi

cat  $(dirname $0)/../../VERSION 2> /dev/null ||echo unknown
