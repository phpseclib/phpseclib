<?php

use phpseclib\Crypt\RSA;

class CreateVariableKey {
  public function createVariableKey(int $size) {
    $rsa = new RSA();
    extract($rsa->createKey($size));
  }
}

?>
-----
<?php

use phpseclib3\Crypt\RSA;

class CreateVariableKey {
  public function createVariableKey(int $size)
  {
      $rsa = RSA::createKey($size);
  }
}

?>
