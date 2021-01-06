<?php

/**
 * Pure-PHP X.509 Parser
 *
 * PHP version 5
 *
 * Encode and decode X.509 certificates.
 *
 * The extensions are from {@link http://tools.ietf.org/html/rfc5280 RFC5280} and
 * {@link http://web.archive.org/web/19961027104704/http://www3.netscape.com/eng/security/cert-exts.html Netscape Certificate Extensions}.
 *
 * Note that loading an X.509 certificate and resaving it may invalidate the signature.  The reason being that the signature is based on a
 * portion of the certificate that contains optional parameters with default values.  ie. if the parameter isn't there the default value is
 * used.  Problem is, if the parameter is there and it just so happens to have the default value there are two ways that that parameter can
 * be encoded.  It can be encoded explicitly or left out all together.  This would effect the signature value and thus may invalidate the
 * the certificate all together unless the certificate is re-signed.
 *
 * @category  File
 * @package   X509
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2012 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\File\Traits;

trait Extensions
{
    /**
     * @var array
     * @access private
     */
    private static $extensions = [];

    /**
     * @var array
     * @access private
     */
    private $extensionValues = [];

    /**
     * Register the mapping for a custom/unsupported extension.
     *
     * @param string $id
     * @param array $mapping
     */
    public static function registerExtension($id, array $mapping)
    {
        self::$extensions[$id] = $mapping;
    }

    /**
     * Register the mapping for a custom/unsupported extension.
     *
     * @param string $id
     * @param mixed $value
     */
    public function setExtensionValue($id, $value)
    {
        $this->extensionValues[$id] = $value;
    }
}
