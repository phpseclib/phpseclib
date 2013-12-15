<?php


class Net_SSH1Test extends PHPUnit_Framework_TestCase
{
    public function formatLogDataProvider() {
        return [
            [['hello world'], ['<--'],
                "<--\r\n00000000  68:65:6c:6c:6f:20:77:6f:72:6c:64                 hello world\r\n\r\n"
            ],
            [['hello', 'world'], ['<--', '<--'],
                "<--\r\n00000000  68:65:6c:6c:6f                                   hello\r\n\r\n" .
                "<--\r\n00000000  77:6f:72:6c:64                                   world\r\n\r\n"
            ],
        ];
    }
    /**
     * @dataProvider formatLogDataProvider
     */
    public function testFormatLog(array $message_log, array $message_number_log, $expected)
    {
        $ssh = $this->getMockBuilder('Net_SSH1')
            ->disableOriginalConstructor()
            ->setMethods(null)
            ->getMock();

        $result = $ssh->_format_log($message_log, $message_number_log);

        $this->assertEquals($expected, $result);
    }
}
