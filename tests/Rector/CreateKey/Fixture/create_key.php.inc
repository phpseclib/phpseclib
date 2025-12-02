<?php

use phpseclib\Crypt\RSA;

function createKey() {
  $rsa = new RSA();
  extract($rsa->createKey(2048));
}

class CreateKey {
  function createKey() {
    $rsa = new RSA();
    extract($rsa->createKey(2048));
  }
}

class CreateNameNotRsa {
  public function createNameNotRsa() {
    $keyGen = new RSA();
    extract($keyGen->createKey(2048));
  }
}

?>
-----
<?php

use phpseclib3\Crypt\RSA;

function createKey()
{
    $rsa = RSA::createKey(2048);
}

class CreateKey {
  function createKey()
  {
      $rsa = RSA::createKey(2048);
  }
}

class CreateNameNotRsa {
  public function createNameNotRsa()
  {
      $keyGen = RSA::createKey(2048);
  }
}

?>
