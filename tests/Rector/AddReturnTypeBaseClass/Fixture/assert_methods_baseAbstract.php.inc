<?php

abstract class BaseClass
{
    abstract public function assertIsArray($param);
}

final class DemoFile extends BaseClass
{
    public function assertIsArray($param)
    {
        echo "hello, world!";
    }
}
?>
-----
<?php

abstract class BaseClass
{
    abstract public function assertIsArray($param): void;
}

final class DemoFile extends BaseClass
{
    public function assertIsArray($param): void
    {
        echo "hello, world!";
    }
}
?>
