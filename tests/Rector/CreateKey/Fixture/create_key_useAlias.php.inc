<?php

use phpseclib\Crypt\RSA as RSACrypt;

class CreateWithAlias {
  public function createWithAlias() {
    $rsa = new RSACrypt();
    extract($rsa->createKey(2048));
  }
}

?>
-----
<?php

use phpseclib3\Crypt\RSA;

class CreateWithAlias {
  public function createWithAlias()
  {
      $privateKey = RSA::createKey(2048);
  }
}

?>
