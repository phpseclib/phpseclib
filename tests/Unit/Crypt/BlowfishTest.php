<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Base;
use phpseclib\Crypt\Blowfish;

class Unit_Crypt_BlowfishTest extends PhpseclibTestCase
{
    public function engineVectors()
    {
        $engines = array(
            Base::ENGINE_INTERNAL => 'internal',
            Base::ENGINE_MCRYPT => 'mcrypt',
            Base::ENGINE_OPENSSL => 'OpenSSL',
        );

        // tests from https://www.schneier.com/code/vectors.txt
        $tests = array(
            // key, plaintext, ciphertext
            array(pack('H*', '0000000000000000'), pack('H*', '0000000000000000'), pack('H*', '4EF997456198DD78')),
            array(pack('H*', 'FFFFFFFFFFFFFFFF'), pack('H*', 'FFFFFFFFFFFFFFFF'), pack('H*', '51866FD5B85ECB8A')),
            array(pack('H*', '3000000000000000'), pack('H*', '1000000000000001'), pack('H*', '7D856F9A613063F2')),
            array(pack('H*', '1111111111111111'), pack('H*', '1111111111111111'), pack('H*', '2466DD878B963C9D')),
            array(pack('H*', '0123456789ABCDEF'), pack('H*', '1111111111111111'), pack('H*', '61F9C3802281B096')),
            array(pack('H*', '1111111111111111'), pack('H*', '0123456789ABCDEF'), pack('H*', '7D0CC630AFDA1EC7')),
            array(pack('H*', '0000000000000000'), pack('H*', '0000000000000000'), pack('H*', '4EF997456198DD78')),
            array(pack('H*', 'FEDCBA9876543210'), pack('H*', '0123456789ABCDEF'), pack('H*', '0ACEAB0FC6A0A28D')),
            array(pack('H*', '7CA110454A1A6E57'), pack('H*', '01A1D6D039776742'), pack('H*', '59C68245EB05282B')),
            array(pack('H*', '0131D9619DC1376E'), pack('H*', '5CD54CA83DEF57DA'), pack('H*', 'B1B8CC0B250F09A0')),
            array(pack('H*', '07A1133E4A0B2686'), pack('H*', '0248D43806F67172'), pack('H*', '1730E5778BEA1DA4')),
            array(pack('H*', '3849674C2602319E'), pack('H*', '51454B582DDF440A'), pack('H*', 'A25E7856CF2651EB')),
            array(pack('H*', '04B915BA43FEB5B6'), pack('H*', '42FD443059577FA2'), pack('H*', '353882B109CE8F1A')),
            array(pack('H*', '0113B970FD34F2CE'), pack('H*', '059B5E0851CF143A'), pack('H*', '48F4D0884C379918')),
            array(pack('H*', '0170F175468FB5E6'), pack('H*', '0756D8E0774761D2'), pack('H*', '432193B78951FC98')),
            array(pack('H*', '43297FAD38E373FE'), pack('H*', '762514B829BF486A'), pack('H*', '13F04154D69D1AE5')),
            array(pack('H*', '07A7137045DA2A16'), pack('H*', '3BDD119049372802'), pack('H*', '2EEDDA93FFD39C79')),
            array(pack('H*', '04689104C2FD3B2F'), pack('H*', '26955F6835AF609A'), pack('H*', 'D887E0393C2DA6E3')),
            array(pack('H*', '37D06BB516CB7546'), pack('H*', '164D5E404F275232'), pack('H*', '5F99D04F5B163969')),
            array(pack('H*', '1F08260D1AC2465E'), pack('H*', '6B056E18759F5CCA'), pack('H*', '4A057A3B24D3977B')),
            array(pack('H*', '584023641ABA6176'), pack('H*', '004BD6EF09176062'), pack('H*', '452031C1E4FADA8E')),
            array(pack('H*', '025816164629B007'), pack('H*', '480D39006EE762F2'), pack('H*', '7555AE39F59B87BD')),
            array(pack('H*', '49793EBC79B3258F'), pack('H*', '437540C8698F3CFA'), pack('H*', '53C55F9CB49FC019')),
            array(pack('H*', '4FB05E1515AB73A7'), pack('H*', '072D43A077075292'), pack('H*', '7A8E7BFA937E89A3')),
            array(pack('H*', '49E95D6D4CA229BF'), pack('H*', '02FE55778117F12A'), pack('H*', 'CF9C5D7A4986ADB5')),
            array(pack('H*', '018310DC409B26D6'), pack('H*', '1D9D5C5018F728C2'), pack('H*', 'D1ABB290658BC778')),
            array(pack('H*', '1C587F1C13924FEF'), pack('H*', '305532286D6F295A'), pack('H*', '55CB3774D13EF201')),
            array(pack('H*', '0101010101010101'), pack('H*', '0123456789ABCDEF'), pack('H*', 'FA34EC4847B268B2')),
            array(pack('H*', '1F1F1F1F0E0E0E0E'), pack('H*', '0123456789ABCDEF'), pack('H*', 'A790795108EA3CAE')),
            array(pack('H*', 'E0FEE0FEF1FEF1FE'), pack('H*', '0123456789ABCDEF'), pack('H*', 'C39E072D9FAC631D')),
            array(pack('H*', '0000000000000000'), pack('H*', 'FFFFFFFFFFFFFFFF'), pack('H*', '014933E0CDAFF6E4')),
            array(pack('H*', 'FFFFFFFFFFFFFFFF'), pack('H*', '0000000000000000'), pack('H*', 'F21E9A77B71C49BC')),
            array(pack('H*', '0123456789ABCDEF'), pack('H*', '0000000000000000'), pack('H*', '245946885754369A')),
            array(pack('H*', 'FEDCBA9876543210'), pack('H*', 'FFFFFFFFFFFFFFFF'), pack('H*', '6B5C5A9C5D9E0A5A'))
        );
        $result = array();
        // @codingStandardsIgnoreStart
        foreach ($engines as $engine => $engineName) 
        foreach ($tests as $test)
            $result[] = array($engine, $engineName, $test[0], $test[1], $test[2]);
        // @codingStandardsIgnoreEnd
        return $result;
    }

    /**
    * @dataProvider engineVectors
    */
    public function testVectors($engine, $engineName, $key, $plaintext, $expected)
    {
        $bf = new Blowfish();
        $bf->setKey($key);
        if (!$bf->isValidEngine($engine)) {
            self::markTestSkipped('Unable to initialize ' . $engineName . ' engine');
        }
        $bf->setPreferredEngine($engine);
        $bf->disablePadding();
        $result = $bf->encrypt($plaintext);
        $plaintext = bin2hex($plaintext);
        $this->assertEquals($result, $expected, "Failed asserting that $plaintext yielded expected output in $engineName engine");
    }
}
