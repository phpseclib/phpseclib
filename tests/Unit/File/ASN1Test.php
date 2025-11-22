<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\File;

use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\MalformedData;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\Common\Functions\Arrays;
use phpseclib4\Tests\PhpseclibTestCase;

class ASN1Test extends PhpseclibTestCase
{
    /**
     * on older versions of \phpseclib4\File\ASN1 this would yield a PHP Warning
     * @group github275
     */
    public function testAnyString(): void
    {
        $KDC_REP = [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'pvno' => [
                    'constant' => 0,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_ANY, ],
                'msg-type' => [
                    'constant' => 1,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_ANY, ],
                'padata' => [
                    'constant' => 2,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_ANY, ],
                'crealm' => [
                    'constant' => 3,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_ANY, ],
                'cname' => [
                    'constant' => 4,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_ANY, ],
                'ticket' => [
                    'constant' => 5,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_ANY, ],
                'enc-part' => [
                    'constant' => 6,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_ANY, ],
            ],
        ];

        $AS_REP = [
            'class'    => ASN1::CLASS_APPLICATION,
            'cast'     => 11,
            'optional' => true,
            'explicit' => true,
        ] + $KDC_REP;

        $str = 'a4IC3jCCAtqgAwIBBaEDAgELoi8wLTAroQMCAROiJAQiMCAwHqADAgEXoRcbFUNSRUFUVUlUWS5ORVR0ZXN0dXNlcqMPGw' .
               '1DUkVBVFVJVFkuTkVUpBUwE6ADAgEBoQwwChsIdGVzdHVzZXKlggFOYYIBSjCCAUagAwIBBaEPGw1DUkVBVFVJVFkuTkVU' .
               'oiIwIKADAgECoRkwFxsGa3JidGd0Gw1DUkVBVFVJVFkuTkVUo4IBCDCCAQSgAwIBF6EDAgEBooH3BIH0AQlxgm/j4z74Ki' .
               'GsJJnROhh8JAiN7pdvlnkxCYKdG6UgdfK/K0NZ+yz+Xg4kgFO1cQ4XYT4Fm3MTmOHzlFmbzlVkUqBI/RnWA9YTREC9Q7Mf' .
               'PPYfRxRG/C6FlahxHCOKj9GUj7bXg7Oq3Sm+QsKTS2bZT05biNf1s7tPCkdIOO0AAd7hvTCpTNAKl+OLN4cpA6pwwk5c3h' .
               '58Ce5/Uri5yBmrfwgkCD5AJUAI/WH56SEEvpifLc6C96w/7y2krAiZm5PyEO0HVhTzUjKGSHoSMb+Z3HI/ul+G9z0Z4qDu' .
               'NjvgP0jKdrKiwWN00NjpiQ0byZd4y6aCASEwggEdoAMCAReiggEUBIIBEHyi8DIbdcfw2DpniBJ3Sh8dDaEbQx+gWx3omC' .
               'TBEyts4sQGTwgQcqkWfeer8M+SkZs/GGZq2YYkyeF+9b6TxlYuX145NuB3KcyzaS7VNrX37E5nGgG8K6r5gTFOhLCqsjjv' .
               'gPXXqLeJo5D1nV+c8BPIEVsu/bbBPgSqpDwUs2mX1WkEg5vfb7kZMC8+LHiRy+sItvIiTtxxEsQ/GEF/ono3hZrEnDa/C+' .
               '4P3wep6uNMLnLzXJmUaAMaopjE+MOcai/t6T9Vg4pERF5Waqwg5ibAbVGK19HuS4LiKiaY3JsyYBuNkEDwiqM7i1Ekw3V+' .
               '+zoEIxqgXjGgPdrWkzU/H6rnXiqMtiZZqUXwWY0zkCmy';

        $decoded = ASN1::decodeBER(base64_decode($str));
        $result = ASN1::map($decoded, $AS_REP)->toArray();

        $this->assertIsArray($result);
    }

    /**
     * on older versions of \phpseclib4\File\ASN1 this would produce a null instead of an array
     * @group github275
     */
    public function testIncorrectString(): void
    {
        $PA_DATA = [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'padata-type' => [
                    'constant' => 1,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_INTEGER,
                ],
                'padata-value' => [
                    'constant' => 2,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_OCTET_STRING,
                ],
            ],
        ];

        $PrincipalName = [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'name-type' => [
                    'constant' => 0,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_INTEGER,
                ],
                'name-string' => [
                    'constant' => 1,
                    'optional' => true,
                    'explicit' => true,
                    'min' => 0,
                    'max' => -1,
                    'type' => ASN1::TYPE_SEQUENCE,
                    'children' => ['type' => ASN1::TYPE_IA5_STRING], // should be \phpseclib4\File\ASN1::TYPE_GENERAL_STRING
                ],
            ],
        ];

        $Ticket = [
            'class'    => ASN1::CLASS_APPLICATION,
            'cast'     => 1,
            'optional' => true,
            'explicit' => true,
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'tkt-vno' => [
                    'constant' => 0,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_INTEGER,
                ],
                'realm' => [
                    'constant' => 1,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_ANY,
                ],
                'sname' => [
                    'constant' => 2,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_ANY,
                ],
                'enc-part' => [
                    'constant' => 3,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_ANY,
                ],
            ],
        ];

        $KDC_REP = [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'pvno' => [
                    'constant' => 0,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_INTEGER, ],
                'msg-type' => [
                     'constant' => 1,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_INTEGER, ],
                'padata' => [
                    'constant' => 2,
                    'optional' => true,
                    'explicit' => true,
                    'min' => 0,
                    'max' => -1,
                    'type' => ASN1::TYPE_SEQUENCE,
                    'children' => $PA_DATA, ],
                'crealm' => [
                    'constant' => 3,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_OCTET_STRING, ],
                'cname' => [
                    'constant' => 4,
                    'optional' => true,
                    'explicit' => true, ] + $PrincipalName,
                    //'type' => ASN1::TYPE_ANY),
                'ticket' => [
                    'constant' => 5,
                    'optional' => true,
                    'implicit' => true,
                    'min' => 0,
                    'max' => 1,
                    'type' => ASN1::TYPE_SEQUENCE,
                    'children' => $Ticket, ],
                'enc-part' => [
                    'constant' => 6,
                    'optional' => true,
                    'explicit' => true,
                    'type' => ASN1::TYPE_ANY, ],
            ],
        ];

        $AS_REP = [
            'class'    => ASN1::CLASS_APPLICATION,
            'cast'     => 11,
            'optional' => true,
            'explicit' => true,
        ] + $KDC_REP;

        $str = 'a4IC3jCCAtqgAwIBBaEDAgELoi8wLTAroQMCAROiJAQiMCAwHqADAgEXoRcbFUNSRUFUVUlUWS5ORVR0ZXN0dXNlcqMPGw' .
               '1DUkVBVFVJVFkuTkVUpBUwE6ADAgEBoQwwChsIdGVzdHVzZXKlggFOYYIBSjCCAUagAwIBBaEPGw1DUkVBVFVJVFkuTkVU' .
               'oiIwIKADAgECoRkwFxsGa3JidGd0Gw1DUkVBVFVJVFkuTkVUo4IBCDCCAQSgAwIBF6EDAgEBooH3BIH0AQlxgm/j4z74Ki' .
               'GsJJnROhh8JAiN7pdvlnkxCYKdG6UgdfK/K0NZ+yz+Xg4kgFO1cQ4XYT4Fm3MTmOHzlFmbzlVkUqBI/RnWA9YTREC9Q7Mf' .
               'PPYfRxRG/C6FlahxHCOKj9GUj7bXg7Oq3Sm+QsKTS2bZT05biNf1s7tPCkdIOO0AAd7hvTCpTNAKl+OLN4cpA6pwwk5c3h' .
               '58Ce5/Uri5yBmrfwgkCD5AJUAI/WH56SEEvpifLc6C96w/7y2krAiZm5PyEO0HVhTzUjKGSHoSMb+Z3HI/ul+G9z0Z4qDu' .
               'NjvgP0jKdrKiwWN00NjpiQ0byZd4y6aCASEwggEdoAMCAReiggEUBIIBEHyi8DIbdcfw2DpniBJ3Sh8dDaEbQx+gWx3omC' .
               'TBEyts4sQGTwgQcqkWfeer8M+SkZs/GGZq2YYkyeF+9b6TxlYuX145NuB3KcyzaS7VNrX37E5nGgG8K6r5gTFOhLCqsjjv' .
               'gPXXqLeJo5D1nV+c8BPIEVsu/bbBPgSqpDwUs2mX1WkEg5vfb7kZMC8+LHiRy+sItvIiTtxxEsQ/GEF/ono3hZrEnDa/C+' .
               '4P3wep6uNMLnLzXJmUaAMaopjE+MOcai/t6T9Vg4pERF5Waqwg5ibAbVGK19HuS4LiKiaY3JsyYBuNkEDwiqM7i1Ekw3V+' .
               '+zoEIxqgXjGgPdrWkzU/H6rnXiqMtiZZqUXwWY0zkCmy';

        $decoded = ASN1::decodeBER(base64_decode($str));
        $result = ASN1::map($decoded, $AS_REP)->toArray();

        $this->assertIsArray($result);
    }

    public function testMaps(): void
    {
        $files = scandir(__DIR__ . '/../../../phpseclib/File/ASN1/Maps');
        self::assertNotEmpty($files);
        foreach ($files as $file) {
            if ($file == '.' || $file == '..') {
                continue;
            }
            self::assertTrue(defined('phpseclib4\\File\\ASN1\\Maps\\' . basename($file, '.php') . '::MAP'));
        }
    }

    public function testApplicationTag(): void
    {
        $map = [
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => [
                // technically, default implies optional, but we'll define it as being optional, none-the-less, just to
                // reenforce that fact
                'version'             => [
                    // if class isn't present it's assumed to be ASN1::CLASS_UNIVERSAL or
                    // (if constant is present) ASN1::CLASS_CONTEXT_SPECIFIC
                    'class'    => ASN1::CLASS_APPLICATION,
                    'cast'     => 2,
                    'optional' => true,
                    'explicit' => true,
                    'default'  => 'v1',
                    'type'     => ASN1::TYPE_INTEGER,
                    'mapping' => ['v1', 'v2', 'v3'],
                ],
            ],
        ];

        $data = ['version' => 'v3'];

        $str = ASN1::encodeDER($data, $map);

        $decoded = ASN1::decodeBER($str);
        $arr = ASN1::map($decoded, $map);

        $this->assertEquals('v3', $arr['version']);
    }

    public function testBigApplicationTag()
    {
        $map = [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'demo' => [
                    'constant' => 0xFFFFFFFF,
                    'optional' => true,
                    'explicit' => true,
                    'default' => 'v1',
                    'type' => ASN1::TYPE_INTEGER,
                    'mapping' => ['v1', 'v2', 'v3'],
                ],
            ],
        ];

        $data = ['demo' => 'v3'];

        $str = ASN1::encodeDER($data, $map);

        $decoded = ASN1::decodeBER($str);
        $arr = ASN1::map($decoded, $map);

        $this->assertEquals('v3', $arr['demo']);
    }

    /**
     * @group github1367
     */
    public function testOIDs(): void
    {
        // from the example in 8.19.5 in the following:
        // https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=22
        $orig = pack('H*', '813403');
        $new = ASN1::decodeOID($orig);
        $this->assertEquals('2.100.3', $new);
        $this->assertSame($orig, ASN1::encodeOID("$new"));

        // UUID OID from the following:
        // https://healthcaresecprivacy.blogspot.com/2011/02/creating-and-using-unique-id-uuid-oid.html
        $orig = '2.25.329800735698586629295641978511506172918';
        $new = ASN1::encodeOID($orig);
        $this->assertSame(pack('H*', '6983f09da7ebcfdee0c7a1a7b2c0948cc8f9d776'), $new);
        $this->assertEquals($orig, ASN1::decodeOID("$new"));
    }

    /**
     * @group github1388
     */
    public function testExplicitImplicitDate(): void
    {
        $map = [
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => [
                'notBefore' => [
                                             'constant' => 0,
                                             'optional' => true,
                                             'implicit' => true,
                                             'type' => ASN1::TYPE_GENERALIZED_TIME, ],
                'notAfter'  => [
                                             'constant' => 1,
                                             'optional' => true,
                                             'implicit' => true,
                                             'type' => ASN1::TYPE_GENERALIZED_TIME, ],
            ],
        ];

        $a = pack('H*', '3026a011180f32303137303432313039303535305aa111180f32303138303432313230353935395a');
        $a = ASN1::decodeBER($a);
        $a = ASN1::map($a, $map)->toArray();

        $this->assertIsArray($a);
    }

    public static function badDecodes(): array
    {
        $bad = [];

        // the following are from CVE-2021-30130
        // see #1635 and https://dl.acm.org/doi/pdf/10.1145/3460120.3485382

        // in phpseclib 3.0 and earlier the following two were in the testNullGarbage() unit test
        $bad[] = [
            '3080305c0609608648016503040201054f8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888804207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9',
            Maps\DigestInfo::MAP,
            'digestAlgorithm',
            'parameters',
        ];
        $bad[] = [
            '3080307f0609608648016503040201057288888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888804207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca90000',
            Maps\DigestInfo::MAP,
            'digestAlgorithm',
            'parameters',
        ];
        // in phpseclib 3.0 and earlier the following two were in the testOIDGarbage() unit test
        $bad[] = [
            '3080305c065860864801650304020188888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888050004207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9',
            Maps\DigestInfo::MAP,
            'digestAlgorithm',
            'algorithm',
        ];
        $bad[] = [
            '3080307f067d608648016503040201888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888804207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9',
            Maps\DigestInfo::MAP,
            'digestAlgorithm',
            'algorithm',
        ];
        // in phpseclib 3.0 and earlier the following four were in the testConstructedMismatch() unit test
        $bad[] = [
            '1031300d0609608648016503040201050004207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9',
            Maps\DigestInfo::MAP,
            null,
            null,
        ];
        $bad[] = [
            '3031100d0609608648016503040201050004207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9',
            Maps\DigestInfo::MAP,
            null,
            'digestAlgorithm',
        ];
        $bad[] = [
            '3031300d2609608648016503040201050004207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9',
            Maps\DigestInfo::MAP,
            'digestAlgorithm',
            'algorithm',
        ];
        $bad[] = [
            '3031300d06096086480165030402012d0004207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9',
            Maps\DigestInfo::MAP,
            'digestAlgorithm',
            'parameters',
        ];
        // in phpseclib 3.0 and earlier the following two were in the testBadTagSecondOctet() unit test
        $bad[] = [
            '3033300f1f808080060960864801650304020104207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9',
            Maps\DigestInfo::MAP,
            null,
            'digestAlgorithm',
        ];
        return $bad;
    }

    /**
     * Test that an exception is thrown on bad decodes
     *
     * @dataProvider badDecodes
     */
    public function testExceptionsOnBadDecodes(string $data, array $map, ?string $path, ?string $key): void
    {
        $this->expectException(\Exception::class);
        $decoded = ASN1::decodeBER(pack('H*', $data));
        $r = ASN1::map($decoded, $map)->toArray();
    }

    /**
     * Test that MalformedData is returned when exceptions are disabled
     *
     * @dataProvider badDecodes
     */
    public function testBlobsOnBadDecodes(string $data, array $map, ?string $path, ?string $key): void
    {
        ASN1::enableBlobsOnBadDecodes();
        $decoded = ASN1::decodeBER(pack('H*', $data));
        $result = ASN1::map($decoded, $map);
        if ($result instanceof Constructed) {
            $result = $result->toArray();
            if (isset($path)) {
                $result = Arrays::subArray($result, $path);
            }
            $result = $result[$key];
        }
        ASN1::disableBlobsOnBadDecodes();
        $this->assertInstanceOf(MalformedData::class, $result);
    }

    /**
     * @group github2104
     */
    public function testBadBigInteger()
    {
        $this->expectException(\Exception::class);
        $key = pack('H*', 'a309486df62e19383a7faecd02423d44fb28773f36403f8a5e3c45f62549c855');
        $decoded = ASN1::decodeBER($key);
        $key = ASN1::map($decoded, \phpseclib4\File\ASN1\Maps\DSAPublicKey::MAP)->toArray();
    }
}
