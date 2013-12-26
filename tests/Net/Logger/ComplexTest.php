<?php
/**
 * @author     Marc Scholten <marc@pedigital.de>
 * @copyright  MMXIII Marc Scholten
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Net_Logger_ComplexTest extends PhpseclibTestCase
{
    public function testLogRemoveTheByteIdentifyingTheMessageType()
    {
        $logger = new Net_Logger_Complex();
        $logger->log('<--', 'Xhello world');
        $this->assertEquals("<--\r\n00000000  68:65:6c:6c:6f:20:77:6f:72:6c:64                 hello world\r\n\r\n", $logger->getLog());
    }

    public function testMaxSize()
    {
        $logger = new Net_Logger_Complex(0);
        $logger->log('hello', 'world');
        $this->assertEquals('', $logger->getLog());
    }

    public function testLoggerIsRemovingGarbageIfOverMaxSize()
    {
        $logger = new Net_Logger_Complex(5);
        $logger->log('hello', '12345');
        $this->assertNotEmpty($logger->getLog());

        $logger->log('world', '6789');
        $this->assertContains('world', $logger->getLog());
    }

}
