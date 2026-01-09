<?php

use phpseclib\Crypt\Hash;

$hash = new Hash('sha512');
echo $hash->getLength();

abstract class BaseClass
{
    abstract public function printLength();
}

final class hashLengthClass extends BaseClass
{
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

abstract class BaseClass
{
    abstract public function printLength();
}

final class hashLengthClass extends BaseClass
{
  function printLength() {
    $hash1 = new Hash('sha512/224');
    echo $hash1->getLengthInBytes();
  }
}

?>
