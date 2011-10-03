extern "C" {
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <php.h>
#include <SAPI.h>
#include <dlfcn.h>
#include <string.h>
#include "zend_exceptions.h"
#include "zend_interfaces.h"

#include "php_btclib.h"
}

#include "cryptopp/cryptlib.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/integer.h"
#include "cryptopp/oids.h"
#include "cryptopp/osrng.h"

#include <string>

/* {{{ proto string btclib_get_public_key(string privkey)
 * Computes the pubic bitcoin key based on private key
 */
PHP_FUNCTION(btclib_get_public_key)
{
	char *privkey;
	int tlen;

	zend_error_handling error_handling;
	zend_replace_error_handling(EH_THROW, NULL, &error_handling TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &privkey, &tlen) == FAILURE) {
		zend_restore_error_handling(&error_handling TSRMLS_CC);
		return;
	}
	zend_restore_error_handling(&error_handling TSRMLS_CC);

	if (tlen != 32) {
		zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Private key must be 32 bytes long", 0 TSRMLS_CC);
		return;
	}

	try {
		CryptoPP::Integer pk((const byte*)privkey, 32, CryptoPP::Integer::UNSIGNED); // private key is 32 bytes (256 bits)
		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

		// init with bitcoin standard curve
		privateKey.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp256k1());
		privateKey.SetPrivateExponent(pk);

		privateKey.MakePublicKey(publicKey);

		char *pubkey = (char*)emalloc(65);

		pubkey[0] = 0x04; // this is a non compressed point
		publicKey.GetPublicElement().x.Encode((byte*)pubkey+1, 32);
		publicKey.GetPublicElement().y.Encode((byte*)pubkey+33, 32);

		RETURN_STRINGL(pubkey, 65, 0);
	} catch(const CryptoPP::Exception& e) {
		zend_throw_exception(zend_exception_get_default(TSRMLS_C), estrdup(e.what()), 0 TSRMLS_CC);
	}
}
/* }}} */

/* {{{ proto string btclib_sign(string buffer, string privkey)
 * Computes the signature for buffer and returns it
 */
PHP_FUNCTION(btclib_sign)
{
	char *buffer, *privkey;
	int blen, tlen;

	zend_error_handling error_handling;

	zend_replace_error_handling(EH_THROW, NULL, &error_handling TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &buffer, &blen, &privkey, &tlen) == FAILURE) {
		zend_restore_error_handling(&error_handling TSRMLS_CC);
		return;
	}

	zend_restore_error_handling(&error_handling TSRMLS_CC);

	if (tlen != 32) {
		zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Private key must be 32 bytes long", 0 TSRMLS_CC);
		return;
	}

	try {
		CryptoPP::Integer pk((const byte*)privkey, 32, CryptoPP::Integer::UNSIGNED); // private key is 32 bytes (256 bits)
		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
		privateKey.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp256k1());
		privateKey.SetPrivateExponent(pk);
		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer sig(privateKey);

		std::string msg(buffer, blen);
		std::string signature;
		CryptoPP::AutoSeededRandomPool prng;

		CryptoPP::StringSource(msg, true, new CryptoPP::SignerFilter(prng, sig, new CryptoPP::StringSink(signature)));

		if (signature.size() != 64) { // uh?
			zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Unexpected length in resulting signature", 0 TSRMLS_CC);
			RETURN_FALSE;
		}

		const char *sig_c = signature.c_str();
		std::string final_signature; // somehow signature is not DER-encoded, let's fix that

		final_signature.append("\x30", 1);
		// add length (44, 45, 46)
		int flen = 0x44;
		if (sig_c[0] < 0) flen++;
		if (sig_c[32] < 0) flen++;
		final_signature.append(1, flen);
		final_signature.append("\x02", 1);
		if (sig_c[0] < 0) {
			final_signature.append("\x21\x00", 2);
			final_signature.append(sig_c, 32);
		} else {
			final_signature.append("\x20", 1);
			final_signature.append(sig_c, 32);
		}
		if (sig_c[32] < 0) {
			final_signature.append("\x02\x21\x00", 3);
			final_signature.append(sig_c+32, 32);
		} else {
			final_signature.append("\x02\x20", 2);
			final_signature.append(sig_c+32, 32);
		}
		final_signature.append("\x01", 1);

		RETURN_STRINGL(final_signature.c_str(), final_signature.size(), 1);
	} catch(const CryptoPP::Exception& e) {
		zend_throw_exception(zend_exception_get_default(TSRMLS_C), estrdup(e.what()), 0 TSRMLS_CC);
	}
}
/* }}} */

/* {{{ btclib_functions[]
 *
 * Every user visible function must have an entry in btclib_functions[].
 */

static zend_function_entry btclib_functions[] = {
	PHP_FE(btclib_get_public_key, NULL)
	PHP_FE(btclib_sign, NULL)
	{NULL, NULL, NULL} /* Must be the last line in btclib_functions[] */
};
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(btclib)
{
/* TODO: why?
	php_info_print_table_start();
	php_info_print_table_header(2, "btclib support", "enabled");
	php_info_print_table_end();
	*/
}

/* {{{ btclib_module_entry
 */
zend_module_entry btclib_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"btclib",
	btclib_functions,
	NULL,
	NULL,
	NULL,
	NULL,
	PHP_MINFO(btclib),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_BTCLIB_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_BTCLIB
extern "C" {
ZEND_GET_MODULE(btclib)
}
#endif

