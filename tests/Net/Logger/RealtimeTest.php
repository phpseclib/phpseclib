<?php
/**
 * @author     Marc Scholten <marc@pedigital.de>
 * @copyright  MMXIII Marc Scholten
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Net_Logger_RealtimeTest extends PhpseclibTestCase
{
    public function testLog()
    {
        $expected = "\r\n<--\r\n00000000  65:6c:6c:6f:20:77:6f:72:6c:64                    ello world\r\n\r\n\r\n";
        $mock = $this->getMockBuilder('Net_Logger_Realtime')
            ->setMethods(['_flush'])
            ->getMock();
        $mock->expects($this->once())
            ->method('_flush')
            ->with($this->equalTo($expected))
        ;

        $mock->log('<--', 'hello world');
    }

    public function testGetLogReturnsNull()
    {
        $logger = new Net_Logger_Realtime();
        $this->assertNull($logger->getLog());
    }
} 
