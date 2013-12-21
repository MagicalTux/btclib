#ifndef PHP_BTCLIB_H
#define PHP_BTCLIB_H

#define PHP_BTCLIB_VERSION "0.1"

extern zend_module_entry btclib_module_entry;
#define phpext_btclib_ptr &btclib_module_entry

PHP_MINFO_FUNCTION(btclib);

PHP_FUNCTION(btclib_get_public_key);
PHP_FUNCTION(btclib_rawsign);

#endif  /* PHP_PROCTITLE_H */



