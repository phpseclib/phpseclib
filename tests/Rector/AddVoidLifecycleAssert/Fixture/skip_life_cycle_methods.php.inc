<?php

namespace Rector\Tests\TypeDeclaration\Rector\AddVoidLifeCycleAssertRector\Fixture;

class LifeCycleMethods
  {
    public static function noChange() {
      print("No change");
    }

    public function setUp($param) {
      // setup with param, no change
    }

    public function tearDownScenario() {
      print("No change");
    }

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
