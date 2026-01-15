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
    $privateKey = RSA::createKey(2048);
    $publicKey = $privateKey->getPublicKey();
    $privateKey = (string) $privateKey;
    $publicKey = (string) $publicKey;
}

class CreateKey {
  function createKey()
  {
      $privateKey = RSA::createKey(2048);
      $publicKey = $privateKey->getPublicKey();
      $privateKey = (string) $privateKey;
      $publicKey = (string) $publicKey;
  }
}

?>
