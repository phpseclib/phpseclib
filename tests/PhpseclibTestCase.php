<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

abstract class PhpseclibTestCase extends PHPUnit_Framework_TestCase
{
    protected $tempFilesToUnlinkOnTearDown = array();

    public function tearDown()
    {
        foreach ($this->tempFilesToUnlinkOnTearDown as $filename) {
            if (file_exists($filename)) {
                unlink($filename);
            }
        }
        parent::tearDown();
    }

    /**
    * Creates a temporary file on the local filesystem with size
    * $number_of_writes * $bytes_per_write.
    *
    * @param int $number_of_writes
    * @param int $bytes_per_write
    *
    * @return string Filename to temporary file
    */
    protected function createTempFile($number_of_writes, $bytes_per_write)
    {
        $filename = tempnam(sys_get_temp_dir(), 'phpseclib-test-');

        $fp = fopen($filename, 'wb');
        for ($i = 0; $i < $number_of_writes; ++$i) {
            fwrite($fp, str_repeat('a', $bytes_per_write));
        }
        fclose($fp);

        $this->assertTrue(file_exists($filename));
        $this->assertSame($number_of_writes * $bytes_per_write, filesize($filename));
        $this->tempFilesToUnlinkOnTearDown[] = $filename;

        return $filename;
    }

    /**
    * @param string $constant
    * @param mixed $expected
    *
    * @return null
    */
    static protected function ensureConstant($constant, $expected)
    {
        if (defined($constant)) {
            $value = constant($constant);

            if ($value !== $expected) {
                if (function_exists('runkit_constant_redefine')) {
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
    static protected function reRequireFile($filename)
    {
        if (function_exists('runkit_import')) {
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
}
