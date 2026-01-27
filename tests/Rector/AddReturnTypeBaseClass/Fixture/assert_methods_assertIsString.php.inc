<?php

use PHPUnit\Framework\Assert;

final class AssertMethods extends Assert
{
  public static function assertIsString($value) {
    print($value);
  }
}
?>
-----
<?php

use PHPUnit\Framework\Assert;

final class AssertMethods extends Assert
{
  public static function assertIsString($value): void {
    print($value);
  }
}
?>
