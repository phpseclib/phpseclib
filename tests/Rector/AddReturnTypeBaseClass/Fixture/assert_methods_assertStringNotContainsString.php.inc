<?php

use PHPUnit\Framework\Assert;

final class AssertMethods extends Assert
{
  public static function assertStringNotContainsString($value) {
    print($value);
  }
}
?>
-----
<?php

use PHPUnit\Framework\Assert;

final class AssertMethods extends Assert
{
  public static function assertStringNotContainsString($value): void {
    print($value);
  }
}
?>
