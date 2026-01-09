<?php
use phpseclib\Crypt\RSA;

class CreateNotRelated {
  public function createNotRelated() {
    extract($this->createFoo());
  }
}

?>
