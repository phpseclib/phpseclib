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

?>
