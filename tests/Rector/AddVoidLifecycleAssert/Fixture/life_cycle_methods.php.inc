<?php

use PHPUnit\Framework\TestCase;

final class LifeCycleMethods extends TestCase
  {
    public static function setUpBeforeClass() {
      print("set up before class");
    }

    public static function setUp() {
      print("set up");
    }

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
    public static function setUpBeforeClass(): void {
      print("set up before class");
    }

    public static function setUp(): void {
      print("set up");
    }

    public static function tearDown(): void {
      print("tear down");
    }
  }

?>
