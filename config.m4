dnl config.m4 for extension btclib

PHP_ARG_ENABLE(btclib, whether to enable btclib support,
[  --enable-btclib              Enable btclib support])

if test "$PHP_BTCLIB" != "no"; then
	PHP_REQUIRE_CXX()
	PHP_SUBST(BTCLIB_SHARED_LIBADD)
	PHP_ADD_LIBRARY(stdc++, 1, BTCLIB_SHARED_LIBADD)
dnl	PHP_EVAL_INCLINE(-Icryptopp)
	PHP_NEW_EXTENSION(btclib, btclib.cpp cryptopp/*.cpp, $ext_shared, , -DNDEBUG -DCRYPTOPP_DLL_ONLY)
fi

