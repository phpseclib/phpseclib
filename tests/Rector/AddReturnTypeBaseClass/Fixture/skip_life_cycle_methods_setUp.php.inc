<?php

use PHPUnit\Framework\TestCase;

final class LifeCycleMethods extends TestCase
  {
    public static function setUp(): void {
      print("set up");
    }
  }

?>
