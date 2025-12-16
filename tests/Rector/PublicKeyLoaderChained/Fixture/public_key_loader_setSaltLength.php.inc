<?php

use phpseclib\Crypt\RSA;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderFunc() {
      $rsa = new RSA();
      $rsa->loadKey('...');
      $rsa->setSaltLength(10);
  }
}

?>
-----
<?php

use phpseclib3\Crypt\PublicKeyLoader;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderFunc()
  {
      $rsa = PublicKeyLoader::load('...')->withSaltLength(10);
  }
}

?>
