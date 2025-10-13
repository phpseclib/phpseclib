<?php

/**
 * Pure-PHP ASN.1 Parser
 *
 * PHP version 5
 *
 * ASN.1 provides the semantics for data encoded using various schemes.  The most commonly
 * utilized scheme is DER or the "Distinguished Encoding Rules".  PEM's are base64 encoded
 * DER blobs.
 *
 * \phpseclib3\File\ASN1 decodes and encodes DER formatted messages and places them in a semantic context.
 *
 * Uses the 1988 ASN.1 syntax.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2012 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\File;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Exception\RuntimeException;
use phpseclib3\Exception\EncodedDataUnavailableException;
use phpseclib3\Exception\EOCException;
use phpseclib3\Exception\InvalidArgumentException;
use phpseclib3\Exception\NoValidTagFoundException;
use phpseclib3\Exception\UnsupportedFormatException;
use phpseclib3\File\ASN1\Constructed;
use phpseclib3\File\ASN1\Element;
use phpseclib3\File\ASN1\MalformedData;
use phpseclib3\File\ASN1\Types\BaseType;
use phpseclib3\File\ASN1\Types\BMPString;
use phpseclib3\File\ASN1\Types\BitString;
use phpseclib3\File\ASN1\Types\Boolean;
use phpseclib3\File\ASN1\Types\Choice;
use phpseclib3\File\ASN1\Types\ExplicitNull;
use phpseclib3\File\ASN1\Types\GeneralString;
use phpseclib3\File\ASN1\Types\GeneralizedTime;
use phpseclib3\File\ASN1\Types\GraphicString;
use phpseclib3\File\ASN1\Types\IA5String;
use phpseclib3\File\ASN1\Types\Integer;
use phpseclib3\File\ASN1\Types\NumericString;
use phpseclib3\File\ASN1\Types\OID;
use phpseclib3\File\ASN1\Types\OctetString;
use phpseclib3\File\ASN1\Types\PrintableString;
use phpseclib3\File\ASN1\Types\TeletexString;
use phpseclib3\File\ASN1\Types\UTCTime;
use phpseclib3\File\ASN1\Types\UTF8String;
use phpseclib3\File\ASN1\Types\UniversalString;
use phpseclib3\File\ASN1\Types\VideotexString;
use phpseclib3\File\ASN1\Types\VisibleString;
use phpseclib3\Math\BigInteger;

/**
 * Pure-PHP ASN.1 Parser
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class ASN1
{
    // Tag Classes
    // http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=12
    public const CLASS_UNIVERSAL        = 0;
    public const CLASS_APPLICATION      = 1;
    public const CLASS_CONTEXT_SPECIFIC = 2;
    public const CLASS_PRIVATE          = 3;

    // Tag Classes
    // http://www.obj-sys.com/asn1tutorial/node124.html
    public const TYPE_BOOLEAN           = 1;
    public const TYPE_INTEGER           = 2;
    public const TYPE_BIT_STRING        = 3;
    public const TYPE_OCTET_STRING      = 4;
    public const TYPE_NULL              = 5;
    public const TYPE_OBJECT_IDENTIFIER = 6;
    //const TYPE_OBJECT_DESCRIPTOR = 7;
    //const TYPE_INSTANCE_OF       = 8; // EXTERNAL
    public const TYPE_REAL              = 9;
    public const TYPE_ENUMERATED        = 10;
    //const TYPE_EMBEDDED          = 11;
    public const TYPE_UTF8_STRING       = 12;
    //const TYPE_RELATIVE_OID      = 13;
    public const TYPE_SEQUENCE          = 16; // SEQUENCE OF
    public const TYPE_SET               = 17; // SET OF

    // More Tag Classes
    // http://www.obj-sys.com/asn1tutorial/node10.html
    public const TYPE_NUMERIC_STRING   = 18;
    public const TYPE_PRINTABLE_STRING = 19;
    public const TYPE_TELETEX_STRING   = 20; // T61String
    public const TYPE_VIDEOTEX_STRING  = 21;
    public const TYPE_IA5_STRING       = 22;
    public const TYPE_UTC_TIME         = 23;
    public const TYPE_GENERALIZED_TIME = 24;
    public const TYPE_GRAPHIC_STRING   = 25;
    public const TYPE_VISIBLE_STRING   = 26; // ISO646String
    public const TYPE_GENERAL_STRING   = 27;
    public const TYPE_UNIVERSAL_STRING = 28;
    //const TYPE_CHARACTER_STRING = 29;
    public const TYPE_BMP_STRING       = 30;

    // Tag Aliases
    // These tags are kinda place holders for other tags.
    public const TYPE_CHOICE = -1;
    public const TYPE_ANY    = -2;

    /**
     * Save as PEM
     *
     * ie. a base64-encoded PEM with a header and a footer
     */
    public const FORMAT_PEM = 0;
    /**
     * Save as DER
     */
    public const FORMAT_DER = 1;
    /**
     * Auto-detect the format
     *
     * Used only by the load*() functions
     */
    public const FORMAT_AUTO_DETECT = 3;

    public const EXCEPTIONS_EVERY_TIME = 0;
    public const BLOB_ON_BAD_ELEMENT = 1;
    public const BLOB_ON_INCOMPLETE_ELEMENT = 2;

    /**
     * ASN.1 object identifiers
     *
     * @var array
     * @link http://en.wikipedia.org/wiki/Object_identifier
     */
    private static array $oids = [];

    /**
     * ASN.1 object identifier reverse mapping
     */
    private static array $reverseOIDs = [];

    /**
     * Have all OIDs been loaded?
     */
    private static bool $allOIDsLoaded = false;

    /**
     * Default date format
     *
     * @var string
     * @link http://php.net/class.datetime
     */
    private static string $format = 'D, d M Y H:i:s O';

    /**
     * Current Location of most recent ASN.1 encode process
     *
     * Useful for debug purposes
     *
     * @see self::encode_der()
     */
    private static array $location;

    /**
     * Use Encoded Cache Flag
     *
     * Only Constructed objects or ASN1\Types\* objects can have an encoded cache
     *
     * @see self::encodeDER()
     */
    private static bool $useEncodedCache = true;

    /**
     * Cache Invalidation Flag
     *
     * Sometimes we want setting an offset in a Constructed object should invalidate the cache,
     * sometimes it shouldn't
     */
    private static bool $invalidateCache = true;

    private static bool $blobsOnBadDecodes = false;

    /*
     * Recursion Depth Limit
     *
     * OpenSSL uses 128. the OpenSSL error reads "BAD RECURSION DEPTH"
     */
    private static int $recursionDepth = 128;

    /**
     * Decode the tag
     *
     * Returns the class, whether or not the tag is primitive or constructed and the tag number
     */
    public static function decodeTag(string $encoded, int &$encoded_pos = 0): array
    {
        if (!isset($encoded[$encoded_pos])) {
            throw new RuntimeException('Not enough bytes to decode tag 1');
        }

        $type = ord($encoded[$encoded_pos++]);
        $offset = 1;

        $constructed = ($type >> 5) & 1;

        $tag = $type & 0x1F;
        if ($tag == 0x1F) {
            $tag = 0;
            // process septets (since the eighth bit is ignored, it's not an octet)
            do {
                if (!isset($encoded[$encoded_pos])) {
                    throw new RuntimeException('Not enough bytes to decode tag 2');
                }
                $temp = ord($encoded[$encoded_pos++]);
                $offset++;
                $loop = $temp >> 7;
                $tag <<= 7;
                $temp &= 0x7F;
                if ($offset == 2 && $temp == 0) {
                    throw new RuntimeException('Bits 7 to 1 of the first subsequent octet shall not be all zero');
                }
                $tag |= $temp;
            } while ($loop);
        }

        $class = ($type >> 6) & 3;

        return compact('constructed', 'tag', 'class');
    }

    /**
     * Decode the length
     *
     * Returns null if the length is of the indefinite form
     */
    public static function decodeLength(string $encoded, int &$encoded_pos = 0): ?int
    {
        // Length, as discussed in paragraph 8.1.3 of X.690-0207.pdf#page=13
        if (!isset($encoded[$encoded_pos])) {
            throw new RuntimeException('Not enough bytes to decode length');
        }
        $length = ord($encoded[$encoded_pos++]);
        if ($length == 0x80) { // indefinite length
            // "[A sender shall] use the indefinite form (see 8.1.3.6) if the encoding is constructed and is not all
            //  immediately available." -- paragraph 8.1.3.2.c
            return null;
        }

        if ($length & 0x80) { // definite length, long form
            // technically, the long form of the length can be represented by up to 126 octets (bytes), but we'll only
            // support it up to four.
            $length &= 0x7F;
            $temp = substr($encoded, $encoded_pos, $length);
            $encoded_pos += $length;
            [, $length] = unpack('N', substr(str_pad($temp, 4, chr(0), STR_PAD_LEFT), -4));
        }

        return $length;
    }

    /**
     * Parse BER-encoding (Helper function)
     *
     * Sometimes we want to get the BER encoding of a particular tag.  $start lets us do that without having to reencode.
     * $encoded is passed by reference for the recursive calls done for self::TYPE_BIT_STRING and
     * self::TYPE_OCTET_STRING. In those cases, the indefinite length is used.
     *
     * $start is the position in the _original_ $encoded string
     * $encoded_pos is the position in the _current_ $encoded string (which may have been passed through substr)
     * in what's returned, length is not set if it's indefinite length. when it is set it does not include the header
     * length.
     *
     * the array that's returned always has the following keys:
     *
     * - start
     * - headerlength
     * - type
     * - content: may be a BaseType object or an Element object
     *
     * keys that *may* be present are:
     *
     * - length: if the definitive length is used. if this is not present you know the indefinite length is being used
     * - constant: if a constant is being used
     */
    public static function decodeBER(string $encoded, int $start = 0, int $encoded_pos = 0): array
    {
        if ($encoded instanceof Element) {
            $encoded = (string) $encoded;
        }

        $current = ['start' => $start];

        $old_encoded_pos = $encoded_pos;
        [
            'constructed' => $constructed,
            'tag' => $tag,
            'class' => $class
        ] = self::decodeTag($encoded, $encoded_pos);
        $length = self::decodeLength($encoded, $encoded_pos);
        $current['headerlength'] = $encoded_pos - $old_encoded_pos;
        if (isset($length)) {
            $current['length'] = $length;
        }

        $start += $current['headerlength'];

        if ($length > (strlen($encoded) - $encoded_pos)) {
            throw new RuntimeException("Length ($length) exceeds number of available bytes (" . (strlen($encoded) - $encoded_pos) . ')');
        }
        $content = substr($encoded, $encoded_pos, $length);
        $headercontent = substr($encoded, $old_encoded_pos, $current['headerlength']);

        // at this point $length can be overwritten. it's only accurate for definite length things as is

        /* Class is UNIVERSAL, APPLICATION, PRIVATE, or CONTEXT-SPECIFIC. The UNIVERSAL class is restricted to the ASN.1
           built-in types. It defines an application-independent data type that must be distinguishable from all other
           data types. The other three classes are user defined. The APPLICATION class distinguishes data types that
           have a wide, scattered use within a particular presentation context. PRIVATE distinguishes data types within
           a particular organization or country. CONTEXT-SPECIFIC distinguishes members of a sequence or set, the
           alternatives of a CHOICE, or universally tagged set members. Only the class number appears in braces for this
           data type; the term CONTEXT-SPECIFIC does not appear.

             -- http://www.obj-sys.com/asn1tutorial/node12.html */
        switch ($class) {
            case self::CLASS_APPLICATION:
            case self::CLASS_PRIVATE:
            case self::CLASS_CONTEXT_SPECIFIC:
                return [
                    'start'    => $start,
                    'type'     => $class,
                    'constant' => $tag,
                    'content'  => $constructed ?
                        new Constructed(
                            $content,
                            $class,
                            $tag,
                            $start,
                            0,
                            $current['headerlength'],
                            substr($encoded, $old_encoded_pos, $current['headerlength']),
                        ) :
                        $content,
                    'length'   => $length,
                ] + $current;
        }

        $current += ['type' => $tag];

        if ($constructed) {
            switch ($tag) {
                // see the following URLs for why GENERALIZED_TIME and UTC_TIME are allowed to be constructed:
                // https://github.com/phpseclib/phpseclib/commit/511f55de3d1d504e4686f9d558a3c10709b413f8
                // https://github.com/phpseclib/phpseclib/issues/1388
                case ASN1::TYPE_GENERALIZED_TIME:
                case ASN1::TYPE_UTC_TIME:
                case ASN1::TYPE_BIT_STRING:
                case ASN1::TYPE_OCTET_STRING:
                case ASN1::TYPE_SEQUENCE:
                case ASN1::TYPE_SET:
                    break;
                default:
                    if (!self::$blobsOnBadDecodes) {
                        throw new RuntimeException("$tag should not have the constructed bit set");
                    }
                    return $current + ['content' => new MalformedData($headercontent . $content)];
            }
            return $current + ['content' => new Constructed(
                $content,
                $class,
                $tag,
                $start,
                $encoded_pos,
                $current['headerlength'],
                substr($encoded, $old_encoded_pos, $current['headerlength'])
             )];
        }

        // decode UNIVERSAL tags
        switch ($tag) {
            case self::TYPE_BOOLEAN:
                if (strlen($content) != 1) {
                    // paragraph 8.2.1
                    if (!self::$blobsOnBadDecodes) {
                        // paragraph 8.8.2
                        throw new RuntimeException('The contents octets shall consist of a single octet for bit strings');
                    }
                    $current['content'] = new Element($headercontent . $content);
                    break;
                }
                $current['content'] = new Boolean((bool) ord($content[0]));
                break;
            case self::TYPE_INTEGER:
            case self::TYPE_ENUMERATED:
                $current['content'] = new Integer($content, -256);
                break;
            case self::TYPE_REAL: // not currently supported
                //throw new UnsupportedFormatException('Real numbers are not supported');
                $current['content'] = new Element($headercontent . $content);
                break;
            case self::TYPE_BIT_STRING:
                // The initial octet shall encode, as an unsigned binary integer with bit 1 as the least significant bit,
                // the number of unused bits in the final subsequent octet. The number shall be in the range zero to
                // seven.
                $current['content'] = new BitString($content);
                break;
            case self::TYPE_OCTET_STRING:
                $current['content'] = new OctetString($content);
                break;
            case self::TYPE_NULL:
                if (strlen($content)) {
                    if (!self::$blobsOnBadDecodes) {
                        // paragraph 8.8.2
                        throw new RuntimeException('The contents octets shall not contain any octets for nulls');
                    }
                    $current['content'] = new MalformedData($headercontent . $content);
                    break;
                }
                $current['content'] = new ExplicitNull();
                break;
            case self::TYPE_SEQUENCE:
            case self::TYPE_SET:
                if (!self::$blobsOnBadDecodes) {
                    throw new RuntimeException('All SEQUENCE and SET tags should be constructed');
                }
                $current['content'] = new MalformedData($headercontent . $content);
                break;
            case self::TYPE_OBJECT_IDENTIFIER:
                try {
                    $current['content'] = self::decodeOID($content);
                } catch (\Exception $e) {
                    if (!self::$blobsOnBadDecodes) {
                        throw $e;
                    }
                    $current['content'] = new MalformedData($headercontent . $content);
                }
                break;
            /* Each character string type shall be encoded as if it had been declared:
               [UNIVERSAL x] IMPLICIT OCTET STRING

                 -- X.690-0207.pdf#page=23 (paragraph 8.21.3)

               Per that, we're not going to do any validation.  If there are any illegal characters in the string,
               we don't really care */
            case self::TYPE_NUMERIC_STRING:
                $current['content'] = new NumericString($content);
                break;
            case self::TYPE_PRINTABLE_STRING:
                $current['content'] = new PrintableString($content);
                break;
            case self::TYPE_TELETEX_STRING:
                $current['content'] = new TeletexString($content);
                break;
            case self::TYPE_VIDEOTEX_STRING:
                $current['content'] = new VideotexString($content);
                break;
            case self::TYPE_VISIBLE_STRING:
                $current['content'] = new VisibleString($content);
                break;
            case self::TYPE_IA5_STRING:
                $current['content'] = new IA5String($content);
                break;
            case self::TYPE_GRAPHIC_STRING:
                $current['content'] = new GraphicString($content);
                break;
            case self::TYPE_GENERAL_STRING:
                $current['content'] = new GeneralString($content);
                break;
            case self::TYPE_UTF8_STRING:
                $current['content'] = new UTF8String($content);
                break;
            case self::TYPE_BMP_STRING:
                $current['content'] = new BMPString($content);
                break;
            case self::TYPE_UTC_TIME:
            case self::TYPE_GENERALIZED_TIME:
                try {
                    $current['content'] = self::decodeTime($content, $tag);
                } catch (\Exception $e) {
                    $current['content'] = new Element($headercontent . $content);
                }
                break;
            default:
                if ($tag === 0 && $length === 0) {
                    throw new EOCException('End-of-content (indefinite form) tag encountered');
                }
                throw new NoValidTagFoundException("An unknown tag ($tag) was encountered");
        }

        // ie. length is the length of the full TLV encoding - it's not just the length of the value
        $current+= ['length' => $start - $current['start']];
        $current['content']->addMetadata([
            'rawheader'=> $headercontent,
            'content' => $content,
        ] + $current);

        $start += $length;

        return $current;
    }

    /**
     * ASN.1 Map for CHOICE type
     */
    private static function mapChoice(array $decoded, array $mapping, array $rules = []): Choice
    {
        foreach ($mapping['children'] as $key => $option) {
            switch (true) {
                case isset($option['constant']) && $option['constant'] == $decoded['constant']:
                case !isset($option['constant']) && $option['type'] == $decoded['type']:
                    return new Choice($key, self::map($decoded, $option, $rules[$key] ?? []));
            }
        }
        throw new RuntimeException('No valid CHOICEs found');
    }

    /**
     * ASN.1 Map
     *
     * Provides an ASN.1 semantic mapping ($mapping) from a parsed BER-encoding to a human readable format.
     */
    public static function map(array $decoded, array $mapping, array $rules = []): Element|BaseType
    {
        //if (isset($mapping['decoder'])) {
        //    return $mapping['decoder']($decoded['content']);
        //}

        if (isset($mapping['explicit'])) {
            if (!$decoded['content'] instanceof Constructed) {
                throw new RuntimeException('Child is explicit but actual data is not constructed');
            }
            $decoded = ASN1::decodeBER($decoded['content']->getEncodedWithoutHeader());
        }

        if (isset($decoded['content']) && $decoded['content'] instanceof Constructed) {
            switch ($mapping['type']) {
                case self::TYPE_CHOICE:
                    return self::mapChoice($decoded, $mapping, $rules);
                case self::TYPE_ANY:
                    throw new EncodedDataUnavailableException('To construct an Element object the original raw encoding needs to be available and it is not');
            }
            $decoded['content']->linkMapping($mapping, $rules);
            if (isset($mapping['implicit'])) {
                $decoded['content']->replaceTag($mapping['type']);
            }
            return $decoded['content'];
        }

        if ($mapping['type'] == self::TYPE_ANY) {
            if (isset($decoded['constant'])) {
                throw new EncodedDataUnavailableException('To construct an Element object the original raw encoding needs to be available and it is not');
            }
            return $decoded['content'];
        }

        if ($mapping['type'] == self::TYPE_CHOICE) {
            return self::mapChoice($decoded, $mapping, $rules);
        }

        if (isset($mapping['implicit']) && !is_object($decoded['content'])) {
            $temp = chr($mapping['type']) . self::encodeLength(strlen($decoded['content'])) . $decoded['content'];
            $temp = self::decodeBER($temp);
            return isset($mapping['mapping']) ? self::applyMap($temp['content'], $mapping['mapping']) : $temp['content'];
        }

        if ($decoded['type'] == $mapping['type']) {
            return isset($mapping['mapping']) ? self::applyMap($decoded['content'], $mapping['mapping']) : $decoded['content'];
        }

        // if $decoded['type'] and $mapping['type'] are both strings, but different types of strings,
        // let it through
        switch (true) {
            case $decoded['type'] < 18: // self::TYPE_NUMERIC_STRING == 18
            case $decoded['type'] > 30: // self::TYPE_BMP_STRING == 30
            case $mapping['type'] < 18:
            case $mapping['type'] > 30:
                break;
            default:
                return $decoded['content'];
        }

        throw new RuntimeException('Unable to perform mapping');
    }

    private static function applyMap(Integer|BitString $content, array $mapping): Integer|BitString
    {
        switch ($content::class) {
            case Integer::class:
                $temp = $content->toString();
                if (strlen($temp) > 1) {
                    throw new RuntimeException('Mapped integers > 255 are not supported');
                }
                $key = (int) $temp;
                if (isset($mapping[$key])) {
                    $content->mappedValue = $mapping[$key];
                }
                break;
            case BitString::class:
                $raw = (string) $content;
                $offset = ord($raw[0]);
                $size = (strlen($raw) - 1) * 8 - $offset;
                /*
                   From X.680-0207.pdf#page=46 (21.7):

                   "When a "NamedBitList" is used in defining a bitstring type ASN.1 encoding rules are free to add (or remove)
                    arbitrarily any trailing 0 bits to (or from) values that are being encoded or decoded. Application designers should
                    therefore ensure that different semantics are not associated with such values which differ only in the number of trailing
                    0 bits."
                */
                $bits = count($mapping) == $size ? [] : array_fill(0, count($mapping) - $size, false);
                for ($i = strlen($raw) - 1; $i > 0; $i--) {
                    $current = ord($raw[$i]);
                    for ($j = $offset; $j < 8; $j++) {
                        $bits[] = (bool) ($current & (1 << $j));
                    }
                    $offset = 0;
                }
                $values = [];
                $map = array_reverse($mapping);
                foreach ($map as $i => $value) {
                    if ($bits[$i]) {
                        $values[] = $value;
                    }
                }
                $content->mappedValue = $values;
        }
        return $content;
    }

    /**
     * Use Encoded Cache
     *
     * The encoded cache is only used when encoding ASN.1 stuff
     */
    public static function useEncodedCache(): void
    {
        self::$useEncodedCache = true;
    }

    /**
     * Ignore Encoded Cache
     *
     * The encoded cache is only used when encoding ASN.1 stuff
     */
    public static function ignoreEncodedCache(): void
    {
        self::$useEncodedCache = false;
    }

    /**
     * Disable Cache Invalidation
     *
     * X.509 extensions are stored as octet strings but phpseclib decodes those based on the extension name.
     * This re-assignment would normally invalidate the cache.
     */
    public static function disableCacheInvalidation(): void
    {
        self::$invalidateCache = false;
    }

    /**
     * Enable Cache Invalidation
     *
     * If you change (for example) the certificate start date the cache'd data should be invalidated for that and for
     * everything up the chain
     */
    public static function enableCacheInvalidation(): void
    {
        self::$invalidateCache = true;
    }

    public static function enableBlobsOnBadDecodes(): void
    {
        self::$blobsOnBadDecodes = true;
    }

    public static function disableBlobsOnBadDecodes(): void
    {
        self::$blobsOnBadDecodes = false;
    }

    public static function isBlobsOnBadDecodesEnabled(): bool
    {
        return self::$blobsOnBadDecodes;
    }

    /**
     * @see File\ASN1\Constructed::offsetSet
     */
    public static function invalidateCache(): bool
    {
        return self::$invalidateCache;
    }

    /**
     * ASN.1 Encode
     *
     * DER-encodes an ASN.1 semantic mapping ($mapping).  Some libraries would probably call this function
     * an ASN.1 compiler.
     *
     * @param Element|string|array $source
     */
    public static function encodeDER($source, array $mapping): string
    {
        self::$location = [];
        return self::encode_der($source, $mapping);
    }

    /**
     * ASN.1 Encode (Helper function)
     *
     * $source can be Element|BaseType|BigInteger|string|array|int|float|bool|null
     * and by array that means any of the non-array types in any combination.
     */
    private static function encode_der(mixed $source, array $mapping, string|int|null $idx = null): string
    {
        if ($source instanceof Element) {
            return $source->value;
        }

        if (is_array($source) && isset($source['content']) && $source['content'] instanceof Constructed && !$source['content']->hasMapping()) {
            return $source['content']->hasWrapping() ? $source['content']->getEncodedWithWrapping() : $source['content']->getEncoded();
        }

        if ($source instanceof BaseType && (self::$useEncodedCache || $source->isCacheForced()) && $source->hasEncoded()) {
            return $source->hasWrapping() ? $source->getEncodedWithWrapping() : $source->getEncoded();
        }

        // do not encode (implicitly optional) fields with value set to default
        //if (isset($mapping['default']) && $source === $mapping['default']) {
        //    return '';
        //}
        if (isset($mapping['default'])) {
            switch (true) {
                case $source === $mapping['default']:
                case $mapping['type'] === ASN1::TYPE_BOOLEAN && $source === (new Boolean($mapping['default'])):
                    return '';
                case $mapping['type'] === ASN1::TYPE_INTEGER && $source instanceof Integer:
                   switch (true) {
                       case isset($mapping['mapping']) && $source->mappedValue === $mapping['default']:
                       case !isset($mapping['mapping']) && $source->toString() == $mapping['default']:
                           return '';
                    }
            }
        }

        if (isset($idx)) {
            self::$location[] = $idx;
        }

        $tag = $mapping['type'];
        switch ($tag) {
            case self::TYPE_SET:    // Children order is not important, thus process in sequence.
            case self::TYPE_SEQUENCE:
                $tag |= 0x20; // set the constructed bit

                // ignore the min and max
                if (isset($mapping['min']) && isset($mapping['max'])) {
                    $value = [];
                    $child = $mapping['children'];
                    foreach ($source as $i => $content) {
                        $value[] = self::encode_der($content, $child, $i);
                    }
                    /* "The encodings of the component values of a set-of value shall appear in ascending order, the encodings being compared
                        as octet strings with the shorter components being padded at their trailing end with 0-octets.
                        NOTE - The padding octets are for comparison purposes only and do not appear in the encodings."

                       -- sec 11.6 of http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf  */
                    if ($mapping['type'] == self::TYPE_SET) {
                        sort($value);
                    }
                    $value = implode('', $value);
                    break;
                }

                $value = '';
                foreach ($mapping['children'] as $key => $child) {
                    switch (true) {
                        case is_array($source) && !array_key_exists($key, $source):
                        case !is_array($source) && !isset($source[$key]):
                            if (!isset($child['optional'])) {
                                throw new RuntimeException(implode('/', array_merge(self::$location, [$key])) . ' is not present and is not optional');
                            }
                            continue 2;
                    }

                    $temp = self::encode_der($source[$key], $child, $key);

                    // An empty child encoding means it has been optimized out.
                    // Else we should have at least one tag byte.
                    if ($temp === '') {
                        continue;
                    }

                    // if isset($child['constant']) is true then isset($child['optional']) should be true as well
                    if (isset($child['constant'])) {
                        /*
                           From X.680-0207.pdf#page=58 (30.6):

                           "The tagging construction specifies explicit tagging if any of the following holds:
                            ...
                            c) the "Tag Type" alternative is used and the value of "TagDefault" for the module is IMPLICIT TAGS or
                            AUTOMATIC TAGS, but the type defined by "Type" is an untagged choice type, an untagged open type, or
                            an untagged "DummyReference" (see ITU-T Rec. X.683 | ISO/IEC 8824-4, 8.3)."
                         */
                        if (isset($child['explicit']) || $child['type'] == self::TYPE_CHOICE) {
                            if ($child['constant'] <= 30) {
                                $subtag = chr((self::CLASS_CONTEXT_SPECIFIC << 6) | 0x20 | $child['constant']);
                            } else {
                                $constant = $child['constant'];
                                $subtag = '';
                                while ($constant > 0) {
                                    $subtagvalue = $constant & 0x7F;
                                    $subtag = (chr(0x80 | $subtagvalue)) . $subtag;
                                    $constant = $constant >> 7;
                                }
                                $subtag[strlen($subtag) - 1] = $subtag[strlen($subtag) - 1] & chr(0x7F);
                                $subtag = chr((self::CLASS_CONTEXT_SPECIFIC << 6) | 0x20 | 0x1F) . $subtag;
                            }
                            $temp = $subtag . self::encodeLength(strlen($temp)) . $temp;
                        } else {
                            $subtag = chr((self::CLASS_CONTEXT_SPECIFIC << 6) | (ord($temp[0]) & 0x20) | $child['constant']);
                            $temp = $subtag . substr($temp, 1);
                        }
                    }
                    $value .= $temp;
                }
                break;
            case self::TYPE_CHOICE:
                foreach ($mapping['children'] as $key => $child) {
                    if (!isset($source[$key])) {
                        continue;
                    }

                    $temp = self::encode_der($source[$key], $child, $key);

                    // An empty child encoding means it has been optimized out.
                    // Else we should have at least one tag byte.
                    if ($temp === '') {
                        continue;
                    }

                    $tag = ord($temp[0]);

                    // if isset($child['constant']) is true then isset($child['optional']) should be true as well
                    if (isset($child['constant'])) {
                        if (isset($child['explicit']) || $child['type'] == self::TYPE_CHOICE) {
                            $subtag = chr((self::CLASS_CONTEXT_SPECIFIC << 6) | 0x20 | $child['constant']);
                            $temp = $subtag . self::encodeLength(strlen($temp)) . $temp;
                        } else {
                            $subtag = chr((self::CLASS_CONTEXT_SPECIFIC << 6) | (ord($temp[0]) & 0x20) | $child['constant']);
                            $temp = $subtag . substr($temp, 1);
                        }
                    }
                }

                if (!isset($temp)) {
                    $options = implode(',', array_keys($mapping['children']));
                    throw new RuntimeException(implode('/', self::$location) . " appears to contain a key that\'s defined in the CHOICE ($options)");
                }

                if (isset($idx)) {
                    array_pop(self::$location);
                }

                if ($temp && isset($mapping['cast'])) {
                    $temp[0] = chr(($mapping['class'] << 6) | ($tag & 0x20) | $mapping['cast']);
                }

                return $temp;
            case self::TYPE_INTEGER:
            case self::TYPE_ENUMERATED:
                if (!is_string($source) && !$source instanceof BigInteger && !is_numeric($source)) {
                    $message = implode('/', self::$location) . ' must be a string, a numeric (is_numeric), or an instance of ' .
                        'either phpseclib3\File\ASN1\Types\Integer or a phpseclib3\Math\BigInteger';
                    throw new RuntimeException($message);
                }
                if (!isset($mapping['mapping'])) {
                    if (is_numeric($source)) {
                        $source = new BigInteger($source);
                    }
                    $value = $source->toBytes(true);
                } else {
                    if ($source instanceof Integer && isset($source->mappedValue)) {
                        $source = $source->mappedValue;
                    } elseif ($source instanceof BigInteger) {
                        throw new RuntimeException('No mapped value provided for ' . implode('/', self::$location));
                    }
                    $value = array_search($source, $mapping['mapping']);
                    if ($value === false) {
                        throw new RuntimeException('Unexpected value encountered for ' . implode('/', self::$location));
                    }
                    $value = new BigInteger($value);
                    $value = $value->toBytes(true);
                }
                if (!strlen($value)) {
                    $value = chr(0);
                }
                break;
            case self::TYPE_UTC_TIME:
            case self::TYPE_GENERALIZED_TIME:
                if (!is_string($source) && !$source instanceof \DateTimeInterface) {
                    $type = is_object($source) ? $source::CLASS : gettype($source);
                    throw new RuntimeException(implode('/', self::$location) . " should be either a string or an instance of DateTimeInterface - $type given");
                }
                if ($tag === self::TYPE_UTC_TIME) {
                    if ($source instanceof GeneralizedTime) {
                        throw new RuntimeException(implode('/', self::$location) . ' has a GeneralizedTime object but is of type UTCTime');
                    }
                } else {
                    if ($source instanceof UTCTime) {
                        throw new RuntimeException(implode('/', self::$location) . ' has a UTCTime object but is of type GeneralizedTime');
                    }
                }
                $format = $tag === self::TYPE_UTC_TIME ? 'y' : 'Y';
                $format .= 'mdHis';
                // if $source does _not_ include timezone information within it then assume that the timezone is GMT
                $date = is_string($source) ? new \DateTime($source, new \DateTimeZone('GMT')) : clone $source;
                // if $source _does_ include timezone information within it then convert the time to GMT
                $date->setTimezone(new \DateTimeZone('GMT'));
                $value = $date->format($format) . 'Z';
                break;
            case self::TYPE_BIT_STRING:
                if (isset($mapping['mapping'])) {
                    if ($source instanceof BitString) {
                        if (!isset($source->mappedValue)) {
                            $value = (string) $source;
                            break;
                        }
                        $source = $source->mappedValue;
                    }
                    if (!is_array($source)) {
                        if (!is_string($source)) {
                            $type = is_object($source) ? $source::CLASS : gettype($source);
                            throw new RuntimeException(implode('/', self::$location) . " should be either a string, an array or an instance of BitString - $type provided");
                        }
                        $value = $source;
                        break;
                    }
                    $bits = array_fill(0, count($mapping['mapping']), 0);
                    $size = 0;
                    for ($i = 0; $i < count($mapping['mapping']); $i++) {
                        if (in_array($mapping['mapping'][$i], $source)) {
                            $bits[$i] = 1;
                            $size = $i;
                        }
                    }

                    if (isset($mapping['min']) && $mapping['min'] >= 1 && $size < $mapping['min']) {
                        $size = $mapping['min'] - 1;
                    }

                    $offset = 8 - (($size + 1) & 7);
                    $offset = $offset !== 8 ? $offset : 0;

                    $value = chr($offset);

                    for ($i = $size + 1; $i < count($mapping['mapping']); $i++) {
                        unset($bits[$i]);
                    }

                    $bits = implode('', array_pad($bits, $size + $offset + 1, 0));
                    $bytes = explode(' ', rtrim(chunk_split($bits, 8, ' ')));
                    foreach ($bytes as $byte) {
                        $value .= chr(bindec($byte));
                    }

                    break;
                }
                if (!is_string($source) && !$source instanceof BitString) {
                    $type = is_object($source) ? $source::CLASS : gettype($source);
                    throw new RuntimeException(implode('/', self::$location) . " should be either a string or an instance of BitString - $type provided");
                }
                $value = (string) $source;
                break;
            case self::TYPE_OCTET_STRING:
                /* The initial octet shall encode, as an unsigned binary integer with bit 1 as the least significant bit,
                   the number of unused bits in the final subsequent octet. The number shall be in the range zero to seven.

                   -- http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=16 */
                if (!Strings::is_stringable($source)) {
                    $type = is_object($source) ? $source::CLASS : gettype($source);
                    throw new RuntimeException(implode('/', self::$location) . " (a $type) could not be converted to a string");
                }
                $value = (string) $source;
                break;
            case self::TYPE_OBJECT_IDENTIFIER:
                $value = self::encodeOID((string) $source);
                break;
            case self::TYPE_ANY:
                $loc = self::$location;
                if (isset($idx)) {
                    array_pop(self::$location);
                }

                switch (true) {
                    case $source instanceof BaseType && $source->hasTypeID():
                        return self::encode_der($source, ['type' => $source->getTypeID()] + $mapping, null);
                    case !isset($source):
                        return self::encode_der(null, ['type' => self::TYPE_NULL] + $mapping, null);
                    case is_int($source):
                    case $source instanceof BigInteger:
                        return self::encode_der($source, ['type' => self::TYPE_INTEGER] + $mapping, null);
                    case is_float($source):
                        return self::encode_der($source, ['type' => self::TYPE_REAL] + $mapping, null);
                    case is_bool($source):
                        return self::encode_der($source, ['type' => self::TYPE_BOOLEAN] + $mapping, null);
                    case is_string($source):
                        return self::encode_der($source, ['type' => self::TYPE_UTF8_STRING] + $mapping, null);
                }
                throw new RuntimeException('Please choose a primitive type or create an ASN1Element for ' . implode('/', $loc));
            case self::TYPE_NULL:
                $value = '';
                break;
            case self::TYPE_NUMERIC_STRING:
            case self::TYPE_TELETEX_STRING:
            case self::TYPE_PRINTABLE_STRING:
            case self::TYPE_UNIVERSAL_STRING:
            case self::TYPE_UTF8_STRING:
            case self::TYPE_BMP_STRING:
            case self::TYPE_IA5_STRING:
            case self::TYPE_VISIBLE_STRING:
            case self::TYPE_VIDEOTEX_STRING:
            case self::TYPE_GRAPHIC_STRING:
            case self::TYPE_GENERAL_STRING:
                if ($source instanceof BaseType && $source->hasTypeID() && $source->getTypeID() != $tag) {
                    throw new RuntimeException('Object type does not match the expected type for ' . implode('/', self::$location));
                }
                $value = (string) $source;
                break;
            case self::TYPE_BOOLEAN:
                if ($source instanceof Boolean) {
                    $source = $source->value;
                }
                if (!is_bool($source)) {
                    throw new RuntimeException('Value is not a Boolean or a bool at ' . implode('/', self::$location));
                }
                $value = $source ? "\xFF" : "\x00";
                break;
            default:
                throw new RuntimeException('Mapping provides no type definition for ' . implode('/', self::$location));
        }

        if (isset($idx)) {
            array_pop(self::$location);
        }

        if (isset($mapping['cast'])) {
            if (isset($mapping['explicit']) || $mapping['type'] == self::TYPE_CHOICE) {
                $value = chr($tag) . self::encodeLength(strlen($value)) . $value;
                $tag = ($mapping['class'] << 6) | 0x20 | $mapping['cast'];
            } else {
                $tag = ($mapping['class'] << 6) | (ord($temp[0]) & 0x20) | $mapping['cast'];
            }
        }

        $header = chr($tag) . self::encodeLength(strlen((string) $value));

        if ($source instanceof BaseType) {
            $source->setEncoded($header, $value);
        }

        return $header . $value;
    }

    /**
     * BER-decode the OID
     *
     * Called by _decode_ber()
     */
    public static function decodeOID(string $content): OID
    {
        // BigInteger's are used because of OIDs like 2.25.329800735698586629295641978511506172918
        // https://healthcaresecprivacy.blogspot.com/2011/02/creating-and-using-unique-id-uuid-oid.html elaborates.
        static $eighty;
        if (!$eighty) {
            $eighty = new BigInteger(80);
        }

        $oid = [];
        $pos = 0;
        $len = strlen($content);

        // see https://github.com/openjdk/jdk/blob/2deb318c9f047ec5a4b160d66a4b52f93688ec42/src/java.base/share/classes/sun/security/util/ObjectIdentifier.java#L55
        if ($len > 4096) {
            throw new RuntimeException('Object Identifier size is limited to 4096 bytes');
        }

        if (ord($content[$len - 1]) & 0x80) {
            throw new RuntimeException('OID is malformed');
        }

        $n = new BigInteger();
        while ($pos < $len) {
            $temp = ord($content[$pos++]);
            $n = $n->bitwise_leftShift(7);
            $n = $n->bitwise_or(new BigInteger($temp & 0x7F));
            if (~$temp & 0x80) {
                $oid[] = $n;
                $n = new BigInteger();
            }
        }
        $part1 = array_shift($oid);
        $first = floor(ord($content[0]) / 40);
        /*
          "This packing of the first two object identifier components recognizes that only three values are allocated from the root
           node, and at most 39 subsequent values from nodes reached by X = 0 and X = 1."

          -- https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=22
        */
        if ($first <= 2) { // ie. 0 <= ord($content[0]) < 120 (0x78)
            array_unshift($oid, ord($content[0]) % 40);
            array_unshift($oid, $first);
        } else {
            array_unshift($oid, $part1->subtract($eighty));
            array_unshift($oid, 2);
        }

        return new OID(implode('.', $oid));
    }

    /**
     * DER-encode the OID
     *
     * Called by _encode_der()
     */
    public static function encodeOID(string $source): string
    {
        static $mask, $zero, $forty;
        if (!$mask) {
            $mask = new BigInteger(0x7F);
            $zero = new BigInteger();
            $forty = new BigInteger(40);
        }

        if (!preg_match('#^\d+(?:\.\d+)+$#', $source)) {
            if (!isset(self::$reverseOIDs[$source])) {
                self::loadAllOIDs();
            }
            $oid = self::$reverseOIDs[$source] ?? false;
        } else {
            $oid = $source;
        }
        if ($oid === false) {
            throw new RuntimeException("$source is an invalid OID");
        }

        $parts = explode('.', $oid);
        $part1 = array_shift($parts);
        $part2 = array_shift($parts);

        if ($part1 > 2) {
            throw new RuntimeException('The first OID subidentifier should be between 0 and 2');
        }
        if ($part1 < 2 && $part2 > 39) {
            throw new RuntimeException('The second OID subidentifier should not be larger than 39 unless the first subidentifier is 2');
        }

        $first = new BigInteger($part1);
        $first = $first->multiply($forty);
        $first = $first->add(new BigInteger($part2));

        array_unshift($parts, $first->toString());

        $value = '';
        foreach ($parts as $part) {
            if (!$part) {
                $temp = "\0";
            } else {
                $temp = '';
                $part = new BigInteger($part);
                while (!$part->equals($zero)) {
                    $submask = $part->bitwise_and($mask);
                    $submask->setPrecision(8);
                    $temp = (chr(0x80) | $submask->toBytes()) . $temp;
                    $part = $part->bitwise_rightShift(7);
                }
                $temp[-1] = $temp[-1] & chr(0x7F);
            }
            $value .= $temp;
        }

        return $value;
    }

    /**
     * BER-decode the time
     *
     * Called by _decode_ber() and in the case of implicit tags map().
     */
    private static function decodeTime(string $content, int $tag): UTCTime|GeneralizedTime
    {
        /* UTCTime:
           http://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
           http://www.obj-sys.com/asn1tutorial/node15.html

           GeneralizedTime:
           http://tools.ietf.org/html/rfc5280#section-4.1.2.5.2
           http://www.obj-sys.com/asn1tutorial/node14.html */

        $format = 'YmdHis';

        if ($tag == self::TYPE_UTC_TIME) {
            // https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=28 says "the seconds
            // element shall always be present" but none-the-less I've seen X509 certs where it isn't and if the
            // browsers parse it phpseclib ought to too
            if (preg_match('#^(\d{10})(Z|[+-]\d{4})$#', $content, $matches)) {
                $content = $matches[1] . '00' . $matches[2];
            }
            $prefix = substr($content, 0, 2) >= 50 ? '19' : '20';
            $content = $prefix . $content;
        } elseif (str_contains($content, '.')) {
            $format .= '.u';
        }

        if ($content[-1] == 'Z') {
            $content = substr($content, 0, -1) . '+0000';
        }

        if (str_contains($content, '-') || str_contains($content, '+')) {
            $format .= 'O';
        }

        $result = $tag == self::TYPE_UTC_TIME ?
            UTCTime::createFromFormat($format, $content) :
            GeneralizedTime::createFromFormat($format, $content);

        if ($result === false) {
            throw new RuntimeException('Unable to parse date time');
        }

        return $result;
    }

    /**
     * Set the time format
     *
     * Sets the time / date format for map().
     */
    public static function setTimeFormat(string $format): void
    {
        self::$format = $format;
    }

    /**
     * Load OIDs
     *
     * Load the relevant OIDs for a particular ASN.1 semantic mapping.
     * Previously loaded OIDs are retained.
     */
    public static function loadOIDs(array|string $oids): bool
    {
        if (is_array($oids)) {
            self::$reverseOIDs += $oids;
            self::$oids = array_flip(self::$reverseOIDs);

            return true;
        }
        $class = 'phpseclib3\File\ASN1\OIDs\\' . $oids;
        if (!class_exists($class)) {
            return false;
        }
        self::$reverseOIDs += $class::OIDs;
        self::$oids = array_flip(self::$reverseOIDs);
        return true;
    }

    /**
     * Load All OIDs
     */
    private static function loadAllOIDs(): void
    {
        if (self::$allOIDsLoaded) {
            return;
        }
        foreach (new \DirectoryIterator(__DIR__ . '/ASN1/OIDs/') as $file) {
            if ($file->getExtension() != 'php') {
                continue;
            }
            $name = $file->getBasename('.php');
            if ($name[0] == '.') {
                continue;
            }
            self::loadOIDs($name);
        }
    }

    /**
     * Extract raw BER from Base64 encoding
     */
    public static function extractBER(string $str): string
    {
        /* X.509 certs are assumed to be base64 encoded but sometimes they'll have additional things in them
         * above and beyond the ceritificate.
         * ie. some may have the following preceding the -----BEGIN CERTIFICATE----- line:
         *
         * Bag Attributes
         *     localKeyID: 01 00 00 00
         * subject=/O=organization/OU=org unit/CN=common name
         * issuer=/O=organization/CN=common name
         */
        if (strlen($str) > ini_get('pcre.backtrack_limit')) {
            $temp = $str;
        } else {
            $temp = preg_replace('#.*?^-+[^-]+-+[\r\n ]*$#ms', '', $str, 1);
            $temp = preg_replace('#-+END.*[\r\n ]*.*#ms', '', $temp, 1);
        }
        // remove new lines
        $temp = str_replace(["\r", "\n", ' '], '', $temp);
        // remove the -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- stuff
        $temp = preg_replace('#^-+[^-]+-+|-+[^-]+-+$#', '', $temp);
        $temp = preg_match('#^[a-zA-Z\d/+]*={0,2}$#', $temp) ? Strings::base64_decode($temp) : false;
        return $temp != false ? $temp : $str;
    }

    /**
     * DER-encode the length
     *
     * DER supports lengths up to (2**8)**127, however, we'll only support lengths up to (2**8)**4.  See
     * {@link http://itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#p=13 X.690 paragraph 8.1.3} for more information.
     */
    public static function encodeLength(int $length): string
    {
        if ($length <= 0x7F) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }

    /**
     * Returns the OID corresponding to a name
     *
     * What's returned in the associative array returned by loadX509() (or load*()) is either a name or an OID if
     * no OID to name mapping is available. The problem with this is that what may be an unmapped OID in one version
     * of phpseclib may not be unmapped in the next version, so apps that are looking at this OID may not be able
     * to work from version to version.
     *
     * This method will return the OID if a name is passed to it and if no mapping is avialable it'll assume that
     * what's being passed to it already is an OID and return that instead. A few examples.
     *
     * getOID('2.16.840.1.101.3.4.2.1') == '2.16.840.1.101.3.4.2.1'
     * getOID('id-sha256') == '2.16.840.1.101.3.4.2.1'
     * getOID('zzz') == 'zzz'
     */
    public static function getOIDFromName(string $name): string
    {
        if (!isset(self::$reverseOIDs[$name])) {
            self::loadAllOIDs();
        }
        return self::$reverseOIDs[$name] ?? $name;
    }

    /**
     * Returns the name corresponding to an OID
     *
     * This method will return the name if an OID is passed to it and if no mapping is avialable it'll assume that
     * what's being passed to it already is a name and will return that instead. A few examples.
     *
     * getOID('2.16.840.1.101.3.4.2.1') == 'id-sha256'
     * getOID('id-sha256') == 'id-sha256'
     * getOID('zzz') == 'zzz'
     */
    public static function getNameFromOID(string $oid): string
    {
        if (!isset(self::$oids[$oid])) {
            self::loadAllOIDs();
        }
        return self::$oids[$oid] ?? $oid;
    }

    /*
     * Extracts the V part of a TLV DER / BER encoded string
     */
    public static function extractValue(string $encoded): string
    {
        $offset = 0;
        ASN1::decodeTag($encoded, $offset);
        $length = ASN1::decodeLength($encoded, $offset);
        return substr($encoded, $offset, $length);
    }

    public static function formatTime(\DateTimeInterface|string $date): array
    {
        if ($date instanceof GeneralizedTime) {
            return ['generalTime' => $date];
        }
        if ($date instanceof UTCTime) {
            return ['utcTime' => $date];
        }
        if ($date instanceof \DateTimeInterface) {
            return ['utcTime' => UTCTime::createFromInterface($date)];
        }
        $date = new UTCTime($date, new \DateTimeZone(@date_default_timezone_get()));
        return ['utcTime' => $date];
    }

    public static function convertTypeConstantToString(int $type): string
    {
        $result = match ($type) {
            1 => 'BOOLEAN',
            2 => 'INTEGER',
            3 => 'BIT STRING',
            4 => 'OCTET STRING',
            5 => 'NULL',
            6 => 'OBJECT IDENTIFIER',
            9 => 'REAL',
            10 => 'ENUMERATED',
            12 => 'UTF8 STRING',
            16 => 'SEQUENCE',
            17 => 'SET',
            18 => 'NUMERIC STRING',
            19 => 'TELETEX STRING',
            21 => 'VIDEOTEX STRING',
            22 => 'IA5 STRING',
            23 => 'UTC TIME',
            24 => 'GENERALIZED TIME',
            25 => 'GRAPHIC STRING',
            26 => 'VISIBLE STRING',
            27 => 'GENERAL STRING',
            28 => 'UNIVERSAL STRING',
            30 => 'BMP STRING',
            default => 'UNKNOWN'
        };
        return "$result ($type)";
    }

    public static function setRecursionDepth(int $depth): void
    {
        self::$recursionDepth = $depth;
    }

    public static function getRecursionDepth(): int
    {
        return self::$recursionDepth;
    }

    public static function convertToPrimitive(BaseType|PublicKey $value): string|null|bool
    {
        return match ($value::class) {
            ExplicitNull::class => null,
            Boolean::class => $value->value,
            default => (string) $value
        };
    }

    /*
    public static function decodeIP(string $val): string|array
    {
        switch (strlen($val)) {
            // this is the format that should be used 99% of the time per
            // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
            case 4:  // IPv4
            case 16: // IPv6
                return inet_ntop($val);
            // in theory the following should only be encountered name constraints per
            // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
            // in practice there's not an easy way to know which is which
            case 8:  // IPv4
            case 32: // IPv6
                $size = strlen($val) >> 1;
                $mask = substr($val, $size);
                $ip = substr($val, 0, $size);
                return [inet_ntop($ip), inet_ntop($mask)];
        }
        throw new RuntimeException('An invalid IP address was encountered');
    }
    */
}
