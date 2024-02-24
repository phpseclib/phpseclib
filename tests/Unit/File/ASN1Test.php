<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'File/ASN1.php';

class Unit_File_ASN1Test extends PhpseclibTestCase
{
    /**
     * on older versions of File_ASN1 this would yield a PHP Warning
     * @group github275
     */
    public function testAnyString()
    {
        $KDC_REP = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'pvno' => array(
                    'constant' => 0,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_ANY),
                'msg-type' => array(
                    'constant' => 1,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_ANY),
                'padata' => array(
                    'constant' => 2,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_ANY),
                'crealm' => array(
                    'constant' => 3,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_ANY),
                'cname' => array(
                    'constant' => 4,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_ANY),
                'ticket' => array(
                    'constant' => 5,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_ANY),
                'enc-part' => array(
                    'constant' => 6,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_ANY)
            )
        );

        $AS_REP = array(
            'class'    => FILE_ASN1_CLASS_APPLICATION,
            'cast'     => 11,
            'optional' => true,
            'explicit' => true
        ) + $KDC_REP;

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

        $asn1 = new File_ASN1();
        $decoded = $asn1->decodeBER(base64_decode($str));
        $result = $asn1->asn1map($decoded[0], $AS_REP);

        $this->assertIsArray($result);
    }

    /**
     * on older versions of File_ASN1 this would produce a null instead of an array
     * @group github275
     */
    public function testIncorrectString()
    {
        $PA_DATA = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'padata-type' => array(
                    'constant' => 1,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_INTEGER
                ),
                'padata-value' => array(
                    'constant' => 2,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_OCTET_STRING
                )
            )
        );

        $PrincipalName = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'name-type' => array(
                    'constant' => 0,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_INTEGER
                ),
                'name-string' => array(
                    'constant' => 1,
                    'optional' => true,
                    'explicit' => true,
                    'min' => 0,
                    'max' => -1,
                    'type' => FILE_ASN1_TYPE_SEQUENCE,
                    'children' => array('type' => FILE_ASN1_TYPE_IA5_STRING) // should be FILE_ASN1_TYPE_GENERAL_STRING
                )
            )
        );

        $Ticket = array(
            'class'    => FILE_ASN1_CLASS_APPLICATION,
            'cast'     => 1,
            'optional' => true,
            'explicit' => true,
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'tkt-vno' => array(
                    'constant' => 0,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_INTEGER
                ),
                'realm' => array(
                    'constant' => 1,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_ANY
                ),
                'sname' => array(
                    'constant' => 2,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_ANY
                ),
                'enc-part' => array(
                    'constant' => 3,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_ANY
                )
            )
        );

        $KDC_REP = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'pvno' => array(
                    'constant' => 0,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_INTEGER),
                'msg-type' => array(
                     'constant' => 1,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_INTEGER),
                'padata' => array(
                    'constant' => 2,
                    'optional' => true,
                    'explicit' => true,
                    'min' => 0,
                    'max' => -1,
                    'type' => FILE_ASN1_TYPE_SEQUENCE,
                    'children' => $PA_DATA),
                'crealm' => array(
                    'constant' => 3,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_OCTET_STRING),
                'cname' => array(
                    'constant' => 4,
                    'optional' => true,
                    'explicit' => true) + $PrincipalName,
                    //'type' => FILE_ASN1_TYPE_ANY),
                'ticket' => array(
                    'constant' => 5,
                    'optional' => true,
                    'implicit' => true,
                    'min' => 0,
                    'max' => 1,
                    'type' => FILE_ASN1_TYPE_SEQUENCE,
                    'children' => $Ticket),
                'enc-part' => array(
                    'constant' => 6,
                    'optional' => true,
                    'explicit' => true,
                    'type' => FILE_ASN1_TYPE_ANY)
            )
        );

        $AS_REP = array(
            'class'    => FILE_ASN1_CLASS_APPLICATION,
            'cast'     => 11,
            'optional' => true,
            'explicit' => true
        ) + $KDC_REP;

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

        $asn1 = new File_ASN1();
        $decoded = $asn1->decodeBER(base64_decode($str));
        $result = $asn1->asn1map($decoded[0], $AS_REP);

        $this->assertIsArray($result);
    }

    /**
     * older versions of File_ASN1 didn't handle indefinite length tags very well
     */
    public function testIndefiniteLength()
    {
        $asn1 = new File_ASN1();
        $decoded = $asn1->decodeBER(file_get_contents(dirname(__FILE__) . '/ASN1/FE.pdf.p7m'));
        $this->assertCount(5, $decoded[0]['content'][1]['content'][0]['content']); // older versions would have returned 3
    }

    public function testDefiniteLength()
    {
        // the following base64-encoded string is the X.509 cert from <http://phpseclib.sourceforge.net/x509/decoder.php>
        $str = 'MIIDITCCAoqgAwIBAgIQT52W2WawmStUwpV8tBV9TTANBgkqhkiG9w0BAQUFADBM' .
               'MQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkg' .
               'THRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0xMTEwMjYwMDAwMDBaFw0x' .
               'MzA5MzAyMzU5NTlaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh' .
               'MRYwFAYDVQQHFA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKFApHb29nbGUgSW5jMRcw' .
               'FQYDVQQDFA53d3cuZ29vZ2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC' .
               'gYEA3rcmQ6aZhc04pxUJuc8PycNVjIjujI0oJyRLKl6g2Bb6YRhLz21ggNM1QDJy' .
               'wI8S2OVOj7my9tkVXlqGMaO6hqpryNlxjMzNJxMenUJdOPanrO/6YvMYgdQkRn8B' .
               'd3zGKokUmbuYOR2oGfs5AER9G5RqeC1prcB6LPrQ2iASmNMCAwEAAaOB5zCB5DAM' .
               'BgNVHRMBAf8EAjAAMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwudGhhd3Rl' .
               'LmNvbS9UaGF3dGVTR0NDQS5jcmwwKAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUF' .
               'BwMCBglghkgBhvhCBAEwcgYIKwYBBQUHAQEEZjBkMCIGCCsGAQUFBzABhhZodHRw' .
               'Oi8vb2NzcC50aGF3dGUuY29tMD4GCCsGAQUFBzAChjJodHRwOi8vd3d3LnRoYXd0' .
               'ZS5jb20vcmVwb3NpdG9yeS9UaGF3dGVfU0dDX0NBLmNydDANBgkqhkiG9w0BAQUF' .
               'AAOBgQAhrNWuyjSJWsKrUtKyNGadeqvu5nzVfsJcKLt0AMkQH0IT/GmKHiSgAgDp' .
               'ulvKGQSy068Bsn5fFNum21K5mvMSf3yinDtvmX3qUA12IxL/92ZzKbeVCq3Yi7Le' .
               'IOkKcGQRCMha8X2e7GmlpdWC1ycenlbN0nbVeSv3JUMcafC4+Q==';
        $asn1 = new File_ASN1();
        $decoded = $asn1->decodeBER(base64_decode($str));
        $this->assertCount(3, $decoded[0]['content']);
    }

    /**
     * @group github477
     */
    public function testContextSpecificNonConstructed()
    {
        $asn1 = new File_ASN1();
        $decoded = $asn1->decodeBER(base64_decode('MBaAFJtUo7c00HsI5EPZ4bkICfkOY2Pv'));
        $this->assertIsString($decoded[0]['content'][0]['content']);
    }

    /**
     * @group github602
     */
    public function testEmptyContextTag()
    {
        $asn1 = new File_ASN1();
        $decoded = $asn1->decodeBER("\xa0\x00");
        $this->assertIsArray($decoded);
        $this->assertCount(0, $decoded[0]['content']);
    }

    /**
     * @group github1027
     */
    public function testInfiniteLoop()
    {
        $asn1 = new File_ASN1();
        $data = base64_decode('MD6gJQYKKwYBBAGCNxQCA6AXDBVvZmZpY2VAY2VydGRpZ2l0YWwucm+BFW9mZmljZUBjZXJ0ZGlnaXRhbC5ybw==');
        $asn1->decodeBER($data);
    }

    public function testApplicationTag()
    {
        $map = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                // technically, default implies optional, but we'll define it as being optional, none-the-less, just to
                // reenforce that fact
                'version'             => array(
                    // if class isn't present it's assumed to be FILE_ASN1_CLASS_UNIVERSAL or
                    // (if constant is present) FILE_ASN1_CLASS_CONTEXT_SPECIFIC
                    'class'    => FILE_ASN1_CLASS_APPLICATION,
                    'cast'     => 2,
                    'optional' => true,
                    'explicit' => true,
                    'default'  => 'v1',
                    'type'     => FILE_ASN1_TYPE_INTEGER,
                    'mapping' => array('v1', 'v2', 'v3')
                )
            )
        );

        $data = array('version' => 'v3');

        $asn1 = new File_ASN1();
        $str = $asn1->encodeDER($data, $map);

        $decoded = $asn1->decodeBER($str);
        $arr = $asn1->asn1map($decoded[0], $map);

        $this->assertSame($data, $arr);
    }

    /**
     * @group github1296
     */
    public function testInvalidCertificate()
    {
        $data = 'a' . base64_decode('MD6gJQYKKwYBBAGCNxQCA6AXDBVvZmZpY2VAY2VydGRpZ2l0YWwucm+BFW9mZmljZUBjZXJ0ZGlnaXRhbC5ybw==');
        $asn1 = new File_ASN1();
        $asn1->decodeBER($data);
    }

    /**
     * @group github1367
     */
    public function testOIDs()
    {
        // from the example in 8.19.5 in the following:
        // https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=22
        $orig = pack('H*', '813403');
        $asn1 = new File_ASN1();
        $new = $asn1->_decodeOID($orig);
        $this->assertSame('2.100.3', $new);
        $this->assertSame($orig, $asn1->_encodeOID($new));

        // UUID OID from the following:
        // https://healthcaresecprivacy.blogspot.com/2011/02/creating-and-using-unique-id-uuid-oid.html
        $orig = '2.25.329800735698586629295641978511506172918';
        $asn1 = new File_ASN1();
        $new = $asn1->_encodeOID($orig);
        $this->assertSame(pack('H*', '6983f09da7ebcfdee0c7a1a7b2c0948cc8f9d776'), $new);
        $this->assertSame($orig, $asn1->_decodeOID($new));
    }

    /**
     * @group github1388
     */
    public function testExplicitImplicitDate()
    {
        $map = array(
            'type'     => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'notBefore' => array(
                                             'constant' => 0,
                                             'optional' => true,
                                             'implicit' => true,
                                             'type' => FILE_ASN1_TYPE_GENERALIZED_TIME),
                'notAfter'  => array(
                                             'constant' => 1,
                                             'optional' => true,
                                             'implicit' => true,
                                             'type' => FILE_ASN1_TYPE_GENERALIZED_TIME)
            )
        );

        $asn1 = new File_ASN1();
        $a = pack('H*', '3026a011180f32303137303432313039303535305aa111180f32303138303432313230353935395a');
        $a = $asn1->decodeBER($a);
        $a = $asn1->asn1map($a[0], $map);

        $this->assertIsArray($a);
    }

    public function testNullGarbage()
    {
        $asn1 = new File_ASN1();

        $em = pack('H*', '3080305c0609608648016503040201054f8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888804207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9');
        $decoded = $asn1->decodeBER($em);
        $this->assertFalse($decoded[0]);

        $em = pack('H*', '3080307f0609608648016503040201057288888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888804207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca90000');
        $decoded = $asn1->decodeBER($em);
        $this->assertFalse($decoded[0]);
    }

    public function testOIDGarbage()
    {
        $asn1 = new File_ASN1();

        $em = pack('H*', '3080305c065860864801650304020188888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888050004207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9');
        $decoded = $asn1->decodeBER($em);
        $this->assertFalse($decoded[0]);

        $em = pack('H*', '3080307f067d608648016503040201888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888804207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9');
        $decoded = $asn1->decodeBER($em);
        $this->assertFalse($decoded[0]);
    }

    public function testConstructedMismatch()
    {
        $asn1 = new File_ASN1();

        $em = pack('H*', '1031300d0609608648016503040201050004207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9');
        $decoded = $asn1->decodeBER($em);
        $this->assertFalse($decoded[0]);

        $em = pack('H*', '3031100d0609608648016503040201050004207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9');
        $decoded = $asn1->decodeBER($em);
        $this->assertFalse($decoded[0]);

        $em = pack('H*', '3031300d2609608648016503040201050004207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9');
        $decoded = $asn1->decodeBER($em);
        $this->assertFalse($decoded[0]);

        $em = pack('H*', '3031300d06096086480165030402012d0004207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9');
        $decoded = $asn1->decodeBER($em);
        $this->assertFalse($decoded[0]);
    }

    public function testBadTagSecondOctet()
    {
        $asn1 = new File_ASN1();

        $em = pack('H*', '3033300f1f808080060960864801650304020104207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9');
        $decoded = $asn1->decodeBER($em);
        $this->assertFalse($decoded[0]);
    }

    public function testLongOID()
    {
        $cert = file_get_contents(dirname(__FILE__) . '/ASN1/mal-cert-02.der');

        $asn1 = new File_ASN1();
        //$this->setExpectedException('PHPUnit_Framework_Error_Notice');
        $decoded = $asn1->decodeBER($cert);
        $this->assertFalse($decoded[0]);

        //$x509 = new X509();
        //$x509->loadX509($cert);
    }
}
