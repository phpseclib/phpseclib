<?php

use phpseclib\Crypt\RSA;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderFunc() {
    $rsa = new RSA();
    extract($rsa->createKey(2048));
  }

}

?>
