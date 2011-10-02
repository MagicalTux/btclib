#!/bin/sh
# Need to do weird stuff on gentoo
export PHP_AUTOCONF="true"
export PHP_AUTOHEADER="true"
phpize
rm -f aclocal.m4
exec 2>/dev/null
aclocal
autoheader
autoconf
