<?php

use phpseclib\Crypt\Hash;

$hash = new Hash('sha512');
echo $hash->getLength();

class hashLengthClass {
  function printLength() {
    $hash1 = new Hash('sha512/224');
    echo $hash1->getLength();
  }
}

?>
-----
<?php

use phpseclib3\Crypt\Hash;

$hash = new Hash('sha512');
echo $hash->getLengthInBytes();

class hashLengthClass {
  function printLength() {
    $hash1 = new Hash('sha512/224');
    echo $hash1->getLengthInBytes();
  }
}

?>
