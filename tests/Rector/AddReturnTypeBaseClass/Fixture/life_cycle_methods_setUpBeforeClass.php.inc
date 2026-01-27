<?php

use PHPUnit\Framework\TestCase;

final class LifeCycleMethods extends TestCase
  {
    public static function setUpBeforeClass() {
      print("set up before class");
    }
  }

?>
-----
<?php

use PHPUnit\Framework\TestCase;

final class LifeCycleMethods extends TestCase
  {
    public static function setUpBeforeClass(): void {
      print("set up before class");
    }
  }

?>
