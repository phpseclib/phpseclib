<?php

use PHPUnit\Framework\Assert;

final class AssertMethods extends Assert
{
  public static function assertIsArray($value) {
    print($value);
  }
}
?>
-----
<?php

use PHPUnit\Framework\Assert;

final class AssertMethods extends Assert
{
  public static function assertIsArray($value): void {
    print($value);
  }
}
?>
