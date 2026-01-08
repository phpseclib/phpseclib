<?php

use PHPUnit\Framework\TestCase;

final class LifeCycleMethods extends TestCase
  {
    public static function tearDown() {
      print("tear down");
    }
  }

?>
-----
<?php

use PHPUnit\Framework\TestCase;

final class LifeCycleMethods extends TestCase
  {
    public static function tearDown(): void {
      print("tear down");
    }
  }

?>
