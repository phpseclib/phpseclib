<?php

use phpseclib\Crypt\RSA;

class CreateMultipleRsa {
  public function createMultipleRsa() {
    $rsa1 = new RSA();
    extract($rsa1->createKey(2048));

    $rsa2 = new RSA();
    extract($rsa2->createKey(1024));
  }
}

?>
-----
<?php

use phpseclib3\Crypt\RSA;

class CreateMultipleRsa {
  public function createMultipleRsa()
  {
      $rsa1 = RSA::createKey(2048);
      $rsa2 = RSA::createKey(1024);
  }
}

?>
