<?php

use phpseclib\Crypt\RSA;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderSetEncryptionAndSignatureMode() {
      $rsa = new RSA();
      $rsa->loadKey('...');
      $rsa->setEncryptionMode(RSA::ENCRYPTION_PKCS1);
      $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
  }
}

?>
-----
<?php

use phpseclib3\Crypt\PublicKeyLoader;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderSetEncryptionAndSignatureMode()
  {
      $rsa = PublicKeyLoader::load('...')->withPadding(RSA::SIGNATURE_PKCS1 | RSA::ENCRYPTION_PKCS1);
  }
}

?>
