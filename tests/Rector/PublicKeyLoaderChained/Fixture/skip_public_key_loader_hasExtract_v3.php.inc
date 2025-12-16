<?php

use phpseclib3\Crypt\RSA;

class PublicKeyLoaderRsav3Class {
  public static function PublicKeyLoaderv3Func() {
    $rsa = new RSA();
    extract($rsa->createKey(2048));
  }
}

?>
