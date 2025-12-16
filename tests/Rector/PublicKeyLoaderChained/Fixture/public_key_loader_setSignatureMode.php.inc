<?php

use phpseclib\Crypt\RSA;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderSetSignatureMode() {
      $rsa = new RSA();
      $rsa->loadKey('...');
      $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
  }
}

?>
-----
<?php

use phpseclib3\Crypt\PublicKeyLoader;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderSetSignatureMode()
  {
      $rsa = PublicKeyLoader::load('...')->withPadding(RSA::SIGNATURE_PKCS1);
  }
}

?>
