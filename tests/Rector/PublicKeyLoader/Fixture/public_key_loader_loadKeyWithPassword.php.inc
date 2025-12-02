<?php

use phpseclib\Crypt\RSA;

class PublicKeyLoaderWithPasswordValue {
  public static function PublicKeyLoaderFunc() {
    $rsa = new RSA();
    $rsa->setPassword($password);
    $rsa->loadKey($privateKey);
  }
}

class PublicKeyLoaderWithPasswordString {
  public static function PublicKeyLoaderFunc() {
    $rsa = new RSA();
    $rsa->setPassword('password');
    $rsa->loadKey('key');
  }
}

?>
-----
<?php

use phpseclib3\Crypt\PublicKeyLoader;

class PublicKeyLoaderWithPasswordValue {
  public static function PublicKeyLoaderFunc()
  {
      $rsa = PublicKeyLoader::load($privateKey, $password);
  }
}

class PublicKeyLoaderWithPasswordString {
  public static function PublicKeyLoaderFunc()
  {
      $rsa = PublicKeyLoader::load('key', 'password');
  }
}

?>
