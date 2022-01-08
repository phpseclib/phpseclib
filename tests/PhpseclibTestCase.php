<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

abstract class PhpseclibTestCase extends PHPUnit\Framework\TestCase
{
    protected $tempFilesToUnlinkOnTearDown = array();

    public function tearDown()
    {
        foreach ($this->tempFilesToUnlinkOnTearDown as $filename) {
            if (!file_exists($filename) || unlink($filename)) {
                unset($this->tempFilesToUnlinkOnTearDown[$filename]);
            }
        }
        parent::tearDown();
    }

    /**
     * Creates a temporary file on the local filesystem and returns its path.
     * The $number_of_writes and $bytes_per_write parameters can be used to
     * write $number_of_writes * $bytes_per_write times the character 'a' to the
     * temporary file. All files created using this method will be deleted from
     * the filesystem on tearDown(), i.e. after each test method was run.
     *
     * @param int $number_of_writes
     * @param int $bytes_per_write
     *
     * @return string
     */
    protected function createTempFile($number_of_writes = 0, $bytes_per_write = 0)
    {
        $filename = tempnam(sys_get_temp_dir(), 'phpseclib-test-');
        $this->assertTrue(file_exists($filename));
        $this->tempFilesToUnlinkOnTearDown[] = $filename;
        if ($number_of_writes > 0 && $bytes_per_write > 0) {
            $fp = fopen($filename, 'wb');
            for ($i = 0; $i < $number_of_writes; ++$i) {
                fwrite($fp, str_repeat('a', $bytes_per_write));
            }
            fclose($fp);
            $this->assertSame($number_of_writes * $bytes_per_write, filesize($filename));
        }
        return $filename;
    }

    /**
     * @param string $constant
     * @param mixed $expected
     *
     * @return null
     */
    protected static function ensureConstant($constant, $expected)
    {
        if (defined($constant)) {
            $value = constant($constant);

            if ($value !== $expected) {
                if (extension_loaded('runkit')) {
                    if (!runkit_constant_redefine($constant, $expected)) {
                        self::markTestSkipped(sprintf(
                            "Failed to redefine constant %s to %s",
                            $constant,
                            $expected
                        ));
                    }
                } else {
                    self::markTestSkipped(sprintf(
                        "Skipping test because constant %s is %s instead of %s",
                        $constant,
                        $value,
                        $expected
                    ));
                }
            }
        } else {
            define($constant, $expected);
        }
    }

    /**
     * @param string $filename
     *
     * @return null
     */
    protected static function reRequireFile($filename)
    {
        if (extension_loaded('runkit')) {
            $result = runkit_import(
                $filename,
                RUNKIT_IMPORT_FUNCTIONS |
                RUNKIT_IMPORT_CLASS_METHODS |
                RUNKIT_IMPORT_OVERRIDE
            );

            if (!$result) {
                self::markTestSkipped("Failed to reimport file $filename");
            }
        }
    }

    // assertIsArray was not introduced until PHPUnit 8
    public static function assertIsArray($actual, $message = '')
    {
        if (method_exists('\PHPUnit\Framework\TestCase', 'assertIsArray')) {
            parent::assertIsArray($actual, $message);
            return;
        }

        parent::assertInternalType('array', $actual, $message);
    }

    // assertIsString was not introduced until PHPUnit 8
    public static function assertIsString($actual, $message = '')
    {
        if (method_exists('\PHPUnit\Framework\TestCase', 'assertIsString')) {
            parent::assertIsString($actual, $message);
            return;
        }

        parent::assertInternalType('string', $actual, $message);
    }

    // assertContains is deprecated for strings in PHPUnit 8
    public static function assertStringContainsString($needle, $haystack, $message = '')
    {
        if (method_exists('\PHPUnit\Framework\TestCase', 'assertStringContainsString')) {
            parent::assertStringContainsString($needle, $haystack, $message);
            return;
        }

        parent::assertContains($needle, $haystack, $message);
    }

    // assertNotContains is deprecated for strings in PHPUnit 8
    public static function assertStringNotContainsString($needle, $haystack, $message = '')
    {
        if (method_exists('\PHPUnit\Framework\TestCase', 'assertStringContainsString')) {
            parent::assertStringNotContainsString($needle, $haystack, $message);
            return;
        }

        parent::assertNotContains($needle, $haystack, $message);
    }

    public function setExpectedException($name, $message = null, $code = null)
    {
        if (version_compare(PHP_VERSION, '7.0.0') < 0) {
            parent::setExpectedException($name, $message, $code);
            return;
        }
        switch ($name) {
            case 'PHPUnit_Framework_Error_Notice':
            case 'PHPUnit_Framework_Error_Warning':
                $name = str_replace('_', '\\', $name);
        }
        $this->expectException($name);
        if (!empty($message)) {
            $this->expectExceptionMessage($message);
        }
        if (!empty($code)) {
            $this->expectExceptionCode($code);
        }
    }
}
