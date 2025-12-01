<?php

namespace Rector\Tests\TypeDeclaration\Rector\AddVoidLifecycleAssert\Fixture;

class AssertMethods
  {
    public static function noChange() {
      print("No change");
    }

    public static function assertIsString() {
      // No parameter, no change
    }
  }

?>
