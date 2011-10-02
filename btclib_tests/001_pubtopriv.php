<?php

// generated with: bin2hex(openssl_random_pseudo_bytes(32))
$privkey = pack('H*', '105465bda78ca5a572c5f705386080461d3e3136075220c12e44feaa6afb14c3');

if (bin2hex(btclib_get_public_key($privkey)) != '04850b8d6238c03905e46df2d7e552926e0e1386a81a662b375e6fc24988b0234b967cb56728392997453bd1f0aba1bbedb5677357f9fd4503eecd9c66aa26c302') exit(1);

