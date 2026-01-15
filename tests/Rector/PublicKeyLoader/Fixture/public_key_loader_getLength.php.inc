<?php

use phpseclib\Crypt\RSA;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderFunc() {
      $rsa = new RSA();
      $rsa->loadKey('...');
      $rsa->getSize();
  }

  public static function PublicKeyLoaderFuncWithEcho() {
      $rsaEcho = new RSA();
      $rsaEcho->loadKey('...');
      echo $rsaEcho->getSize();
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
      $rsa->getLength();
  }

  public static function PublicKeyLoaderFuncWithEcho() {
      $rsaEcho = PublicKeyLoader::load('...');
      echo $rsaEcho->getLength();
  }
}

?>
