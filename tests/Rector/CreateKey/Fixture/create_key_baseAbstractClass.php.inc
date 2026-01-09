<?php

use phpseclib\Crypt\RSA;

abstract class BaseClass
{
    abstract public function createKey();
}

final class CreateKeyClass extends BaseClass
{
  function createKey() {
    $rsa = new RSA();
    extract($rsa->createKey(2048));
  }
}

?>
-----
<?php

use phpseclib3\Crypt\RSA;

abstract class BaseClass
{
    abstract public function createKey();
}

final class CreateKeyClass extends BaseClass
{
  function createKey()
  {
      $rsa = RSA::createKey(2048);
  }
}

?>
