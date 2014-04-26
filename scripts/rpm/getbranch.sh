#!/bin/bash

if [ -d '.svn' ]; then
    # We SVN, take revision number
    ( svn info 2>/dev/null | grep 'Last Changed Rev:' 2>/dev/null | cut -d ':' -f 2 2>/dev/null | tr -d ' ' 2>/dev/null || echo 'unknown' ) > $(dirname $0)/../../BRANCH
elif [ -d "$(dirname $0)/../../.git" ]; then
    # We use git, take the short sha string
    (( branch=$(git branch -a|grep "^[*] ") && echo "${branch##* }" ) || echo 'unknown') > $(dirname $0)/../../BRANCH
fi

cat  $(dirname $0)/../../BRANCH 2> /dev/null ||echo unknown
