<?php

// generated with: bin2hex(openssl_random_pseudo_bytes(32))
$privkey = pack('H*', '105465bda78ca5a572c5f705386080461d3e3136075220c12e44feaa6afb14c3');

var_dump(bin2hex(btclib_sign("Hello", $privkey)));

