<?php

use phpseclib\Crypt\RSA;

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

class CreateNameNotRsa {
  public function createNameNotRsa()
  {
      $keyGen = RSA::createKey(2048);
  }
}

?>
