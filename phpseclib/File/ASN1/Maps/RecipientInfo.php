<?php

/**
 * RecipientInfo
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Maps;

use phpseclib4\File\ASN1;

/**
 * RecipientInfo
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class RecipientInfo
{
    public const MAP = [
        'type' => ASN1::TYPE_CHOICE,
        'children' => [
            'ktri' => [
                //'constant' => 0,
                'optional' => true,
                'implicit' => true,
            ] + KeyTransRecipientInfo::MAP,
            'kari' => [
                'constant' => 1,
                'optional' => true,
                'implicit' => true,
            ] + KeyAgreeRecipientInfo::MAP,
            'kekri' => [
                'constant' => 2,
                'optional' => true,
                'implicit' => true,
            ] + KEKRecipientInfo::MAP,
            'pwri' => [
                'constant' => 3,
                'optional' => true,
                'implicit' => true,
            ] + PasswordRecipientInfo::MAP,
            'ori' => [
                'constant' => 4,
                'optional' => true,
                'implicit' => true,
            ] + OtherRecipientInfo::MAP,
        ],
    ];
}
