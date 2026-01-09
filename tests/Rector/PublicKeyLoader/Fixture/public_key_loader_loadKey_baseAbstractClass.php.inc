<?php

use phpseclib\Crypt\RSA;

abstract class BaseClass
{
    abstract public function PublicKeyLoaderFunc();
}

final class PublicKeyLoaderRsaClass extends BaseClass
{
  function PublicKeyLoaderFunc() {
      $rsa = new RSA();
      $rsa->loadKey($privateKey);
  }
}

?>
-----
<?php

use phpseclib3\Crypt\PublicKeyLoader;

abstract class BaseClass
{
    abstract public function PublicKeyLoaderFunc();
}

final class PublicKeyLoaderRsaClass extends BaseClass
{
  function PublicKeyLoaderFunc()
  {
      $rsa = PublicKeyLoader::load($privateKey);
  }
}

?>
