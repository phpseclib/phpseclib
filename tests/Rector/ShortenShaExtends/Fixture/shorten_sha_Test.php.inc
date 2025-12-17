<?php

class SpecialSHA512Test extends Unit_Crypt_Hash_SHA512Test
{
  public function foo() {
  }
}

class SpecialSHA256Test extends Unit_Crypt_Hash_SHA256Test
{
  public function foo() {
  }
}

?>
-----
<?php

class SpecialSHA512Test extends SHA512Test
{
  public function foo() {
  }
}

class SpecialSHA256Test extends SHA256Test
{
  public function foo() {
  }
}

?>
