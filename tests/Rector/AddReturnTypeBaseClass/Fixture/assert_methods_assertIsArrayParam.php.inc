<?php

use PHPUnit\Framework\Assert;

final class AssertMethods extends Assert
{
  public static function assertIsArray($value): bool {
    // bool -> void
  }
}
?>
-----
<?php

use PHPUnit\Framework\Assert;

final class AssertMethods extends Assert
{
  public static function assertIsArray($value): void {
    // bool -> void
  }
}
?>
