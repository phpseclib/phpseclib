<?php

use phpseclib\Crypt\RSA;

class CreateNoExtract {
  public function createNoExtract() {
    $extractrsa = new RSA();
    $keys = $extractrsa->createKey(2048);
  }
}

?>
