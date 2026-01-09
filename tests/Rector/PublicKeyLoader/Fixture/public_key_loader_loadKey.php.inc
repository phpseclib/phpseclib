<?php

use phpseclib\Crypt\RSA;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderFunc() {
      $rsa = new RSA();
      $rsa->loadKey($privateKey);
  }
}

?>
-----
<?php

use phpseclib3\Crypt\PublicKeyLoader;

class PublicKeyLoaderRsaClass {
  public static function PublicKeyLoaderFunc()
  {
      $rsa = PublicKeyLoader::load($privateKey);
  }
}

?>
