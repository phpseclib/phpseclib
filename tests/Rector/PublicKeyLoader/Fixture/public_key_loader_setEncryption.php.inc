<?php

use phpseclib\Crypt\RSA;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderSetEncryption() {
      $rsa = new RSA();
      $rsa->loadKey('...');
      $rsa->setEncryptionMode(RSA::ENCRYPTION_PKCS1);
  }
}

?>
-----
<?php

use phpseclib3\Crypt\PublicKeyLoader;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderSetEncryption()
  {
      $rsa = PublicKeyLoader::load('...');
      $rsa->withPadding(RSA::ENCRYPTION_PKCS1);
  }
}

?>
