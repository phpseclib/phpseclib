<?php

use phpseclib\Crypt\RSA as RSACrypt;

class PublicKeyLoaderAuthClass {
  public static function PublicKeyLoaderFunc() {
    $rsa = new RSACrypt();
    $rsa->loadKey('foo');
  }
}

?>
-----
<?php

use phpseclib3\Crypt\PublicKeyLoader;

class PublicKeyLoaderAuthClass {
  public static function PublicKeyLoaderFunc()
  {
      $rsa = PublicKeyLoader::load('foo');
  }
}

?>
