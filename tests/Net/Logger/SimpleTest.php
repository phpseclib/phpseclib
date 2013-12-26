<?php
/**
 * @author     Marc Scholten <marc@pedigital.de>
 * @copyright  MMXIII Marc Scholten
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Net_Logger_SimpleTest extends PhpseclibTestCase
{
    public function testGetLogIsReturningArray()
    {
        $logger = new Net_Logger_Simple();
        $this->assertTrue(is_array($logger->getLog()), 'getLog() should return an array');
    }

    public function testLog()
    {
        $logger = new Net_Logger_Simple();
        $logger->log('<--', 'hello world');
        $this->assertEquals(['<--'], $logger->getLog());
    }
} 
