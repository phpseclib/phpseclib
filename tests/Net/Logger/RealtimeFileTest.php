<?php
/**
 * @author     Marc Scholten <marc@pedigital.de>
 * @copyright  MMXIII Marc Scholten
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Net_Logger_RealtimeFileTest extends PhpseclibTestCase
{
    public function testGetLogReturnsNull()
    {
        $mock = $this->getMockBuilder('Net_Logger_RealtimeFile')
            ->setMethods(null)
            ->disableOriginalConstructor()
            ->getMock();

        $this->assertNull($mock->getLog());
    }

    /**
     * @expectedException PHPUnit_Framework_Error
     */
    public function testErrorWhenFileDoesNotExists()
    {
        $logger = new Net_Logger_RealtimeFile('');
    }

    public function testLog()
    {
        $file = tempnam(sys_get_temp_dir(), __CLASS__);
        $logger = new Net_Logger_RealtimeFile($file);
        $logger->log('<--', 'hello world');

        $this->assertNotEmpty(file_get_contents($file));
        $this->assertContains('ello world', file_get_contents($file));
    }

    public function testLogWithSizeOverflowContainsStartMark()
    {
        $file = tempnam(sys_get_temp_dir(), __CLASS__);
        $logger = new Net_Logger_RealtimeFile($file, 10);

        $logger->log('<--', 'hello world');
        $logger->log('<--', 'hello world');
        $logger->log('<--', 'hello world');

        $this->assertContains('<<< START >>>', file_get_contents($file));
    }
} 
