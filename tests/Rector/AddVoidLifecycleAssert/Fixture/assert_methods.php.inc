<?php

class AssertMethods
{
  public static function assertIsArray($value) {
    print($value);
  }

  public static function assertIsString($value) {
    print($value);
  }

  public static function assertStringContainsString($value) {
    print($value);
  }

  public static function assertStringNotContainsString($value) {
    print($value);
  }

  public static function assertIsArray($value): bool {
    // bool -> void
  }
}
?>
-----
<?php

class AssertMethods
{
  public static function assertIsArray($value): void {
    print($value);
  }

  public static function assertIsString($value): void {
    print($value);
  }

  public static function assertStringContainsString($value): void {
    print($value);
  }

  public static function assertStringNotContainsString($value): void {
    print($value);
  }

  public static function assertIsArray($value): void {
    // bool -> void
  }
}
?>