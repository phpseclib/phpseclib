<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright MMXIV Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'File/ASN1.php';

class File_ASN1_DevTest extends PhpseclibTestCase
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

        $this->assertInternalType('array', $result);
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

        $this->assertInternalType('array', $result);
    }
}
