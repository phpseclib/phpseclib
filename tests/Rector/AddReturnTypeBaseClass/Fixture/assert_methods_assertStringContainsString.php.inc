<?php

use PHPUnit\Framework\Assert;

final class AssertMethods extends Assert
{
  public static function assertStringContainsString($value) {
    print($value);
  }
}
?>
-----
<?php

use PHPUnit\Framework\Assert;

final class AssertMethods extends Assert
{
  public static function assertStringContainsString($value): void {
    print($value);
  }
}
?>
