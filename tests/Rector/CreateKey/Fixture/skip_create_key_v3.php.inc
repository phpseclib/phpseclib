<?php

use phpseclib3\Crypt\RSA;

class CreateKeyV3 {
  public function createKeyV3() {
    $rsa = RSA::createKey(2048);
  }
}

?>
