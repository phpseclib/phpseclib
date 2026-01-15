<?php

use phpseclib\Crypt\RSA;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderFunc() {
      $rsa = new RSA();
      $rsa->loadKey('...');
      $rsa->setHash('sha256');
      $rsa->setMGFHash('sha256');
  }
}

?>
-----
<?php

use phpseclib3\Crypt\PublicKeyLoader;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderFunc()
  {
      $rsa = PublicKeyLoader::load('...');
      $rsa = $rsa->withHash('sha256');
      $rsa = $rsa->withMGFHash('sha256');
  }
}

?>
