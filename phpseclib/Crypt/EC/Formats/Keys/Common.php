<?php

/**
 * Generic EC Key Parsing Helper functions
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\EC\Formats\Keys;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\EC\BaseCurves\Base as BaseCurve;
use phpseclib4\Crypt\EC\BaseCurves\Binary as BinaryCurve;
use phpseclib4\Crypt\EC\BaseCurves\Prime as PrimeCurve;
use phpseclib4\Crypt\EC\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\Exception\UnsupportedCurveException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\ASN1\OIDs\Curves;
use phpseclib4\Math\BigInteger;

/**
 * Generic EC Key Parsing Helper functions
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
trait Common
{
    /**
     * Child OIDs loaded
     */
    protected static bool $childOIDsLoaded = false;

    /**
     * Use Named Curves
     */
    private static bool $useNamedCurves = true;

    private static bool $oidsLoaded = false;

    /**
     * Initialize static variables
     */
    private static function initialize_static_variables(): void
    {
        if (!self::$oidsLoaded) {
            ASN1::loadOIDs('Curves');
            ASN1::loadOIDs('EC');
            self::$oidsLoaded = true;
        }
    }

    /**
     * Explicitly set the curve
     *
     * If the key contains an implicit curve phpseclib needs the curve
     * to be explicitly provided
     */
    public static function setImplicitCurve(BaseCurve $curve): void
    {
        self::$implicitCurve = $curve;
    }

    /**
     * Returns an instance of \phpseclib4\Crypt\EC\BaseCurves\Base based
     * on the curve parameters
     *
     * @return BaseCurve|false
     */
    protected static function loadCurveByParam(array $params)
    {
        if (count($params) > 1) {
            throw new RuntimeException('No parameters are present');
        }
        if (isset($params['namedCurve'])) {
            $curve = '\phpseclib4\Crypt\EC\Curves\\' . $params['namedCurve'];
            if (!class_exists($curve)) {
                throw new UnsupportedCurveException('Named Curve of ' . $params['namedCurve'] . ' is not supported');
            }
            return new $curve();
        }
        if (isset($params['implicitCurve'])) {
            if (!isset(self::$implicitCurve)) {
                throw new RuntimeException('Implicit curves can be provided by calling setImplicitCurve');
            }
            return self::$implicitCurve;
        }
        if (isset($params['specifiedCurve'])) {
            $data = $params['specifiedCurve'];
            switch ($data['fieldID']['fieldType']) {
                case 'prime-field':
                    $curve = new PrimeCurve();
                    $curve->setModulo($data['fieldID']['parameters']);
                    $curve->setCoefficients(
                        new BigInteger((string) $data['curve']['a'], 256),
                        new BigInteger((string) $data['curve']['b'], 256)
                    );
                    $point = self::extractPoint("\0" . $data['base'], $curve);
                    $curve->setBasePoint(...$point);
                    $curve->setOrder($data['order']);
                    return $curve;
                case 'characteristic-two-field':
                    $curve = new BinaryCurve();
                    $params = ASN1::decodeBER($data['fieldID']['parameters']->value);
                    $params = ASN1::map($params, Maps\Characteristic_two::MAP)->toArray();
                    $modulo = [(int) $params['m']->toString()];
                    switch ($params['basis']) {
                        case 'tpBasis':
                            $modulo[] = (int) $params['parameters']->toString();
                            break;
                        case 'ppBasis':
                            $temp = ASN1::decodeBER($params['parameters']->value);
                            $temp = ASN1::map($temp, Maps\Pentanomial::MAP)->toArray();
                            $modulo[] = (int) $temp['k3']->toString();
                            $modulo[] = (int) $temp['k2']->toString();
                            $modulo[] = (int) $temp['k1']->toString();
                    }
                    $modulo[] = 0;
                    $curve->setModulo(...$modulo);
                    $len = ceil($modulo[0] / 8);
                    $curve->setCoefficients(
                        Strings::bin2hex((string) $data['curve']['a']),
                        Strings::bin2hex((string) $data['curve']['b'])
                    );
                    $point = self::extractPoint("\0" . $data['base'], $curve);
                    $curve->setBasePoint(...$point);
                    $curve->setOrder($data['order']);
                    return $curve;
                default:
                    throw new UnsupportedCurveException('Field Type of ' . $data['fieldID']['fieldType'] . ' is not supported');
            }
        }
        throw new RuntimeException('No valid parameters are present');
    }

    /**
     * Extract points from a string
     *
     * Supports both compressed and uncompressed points
     *
     * @return object[]
     */
    public static function extractPoint(string $str, BaseCurve $curve): array
    {
        if ($curve instanceof TwistedEdwardsCurve) {
            // first step of point deciding as discussed at the following URL's:
            // https://tools.ietf.org/html/rfc8032#section-5.1.3
            // https://tools.ietf.org/html/rfc8032#section-5.2.3
            $y = $str;
            $y = strrev($y);
            $sign = (bool) (ord($y[0]) & 0x80);
            $y[0] = $y[0] & chr(0x7F);
            $y = new BigInteger($y, 256);
            if ($y->compare($curve->getModulo()) >= 0) {
                throw new RuntimeException('The Y coordinate should not be >= the modulo');
            }
            $point = $curve->recoverX($y, $sign);
            if (!$curve->verifyPoint($point)) {
                throw new RuntimeException('Unable to verify that point exists on curve');
            }
            return $point;
        }

        // the first byte of a bit string represents the number of bits in the last byte that are to be ignored but,
        // currently, bit strings wanting a non-zero amount of bits trimmed are not supported
        if (($val = Strings::shift($str)) != "\0") {
            throw new UnexpectedValueException('extractPoint expects the first byte to be null - not ' . Strings::bin2hex($val));
        }
        if ($str == "\0") {
            return [];
        }

        $keylen = strlen($str);
        $order = $curve->getLengthInBytes();
        // point compression is being used
        if ($keylen == $order + 1) {
            return $curve->derivePoint($str);
        }

        // point compression is not being used
        if ($keylen == 2 * $order + 1) {
            preg_match("#(.)(.{{$order}})(.{{$order}})#s", $str, $matches);
            [, $w, $x, $y] = $matches;
            if ($w != "\4") {
                throw new UnexpectedValueException('The first byte of an uncompressed point should be 04 - not ' . Strings::bin2hex($val));
            }
            $point = [
                $curve->convertInteger(new BigInteger($x, 256)),
                $curve->convertInteger(new BigInteger($y, 256)),
            ];

            if (!$curve->verifyPoint($point)) {
                throw new RuntimeException('Unable to verify that point exists on curve');
            }

            return $point;
        }

        throw new UnexpectedValueException('The string representation of the points is not of an appropriate length');
    }

    /**
     * Encode Parameters
     *
     * @todo Maybe at some point this could be moved to __toString() for each of the curves?
     */
    private static function encodeParameters(BaseCurve $curve, bool $returnArray = false, array $options = []): string|array
    {
        $useNamedCurves = $options['namedCurve'] ?? self::$useNamedCurves;

        $reflect = new \ReflectionClass($curve);
        $name = $reflect->getShortName();
        if ($useNamedCurves) {
            if (isset(Curves::OIDs[$name])) {
                if ($reflect->isFinal()) {
                    $reflect = $reflect->getParentClass();
                    $name = $reflect->getShortName();
                }
                return $returnArray ?
                    ['namedCurve' => $name] :
                    ASN1::encodeDER(['namedCurve' => $name], Maps\ECParameters::MAP);
            }
            foreach (new \DirectoryIterator(__DIR__ . '/../../Curves/') as $file) {
                if ($file->getExtension() != 'php') {
                    continue;
                }
                $testName = $file->getBasename('.php');
                $class = 'phpseclib4\Crypt\EC\Curves\\' . $testName;
                $reflect = new \ReflectionClass($class);
                if ($reflect->isFinal()) {
                    continue;
                }
                $candidate = new $class();
                switch ($name) {
                    case 'Prime':
                        if (!$candidate instanceof PrimeCurve) {
                            break;
                        }
                        if (!$candidate->getModulo()->equals($curve->getModulo())) {
                            break;
                        }
                        if ($candidate->getA()->toBytes() != $curve->getA()->toBytes()) {
                            break;
                        }
                        if ($candidate->getB()->toBytes() != $curve->getB()->toBytes()) {
                            break;
                        }

                        [$candidateX, $candidateY] = $candidate->getBasePoint();
                        [$curveX, $curveY] = $curve->getBasePoint();
                        if ($candidateX->toBytes() != $curveX->toBytes()) {
                            break;
                        }
                        if ($candidateY->toBytes() != $curveY->toBytes()) {
                            break;
                        }

                        return $returnArray ?
                            ['namedCurve' => $testName] :
                            ASN1::encodeDER(['namedCurve' => $testName], Maps\ECParameters::MAP);
                    case 'Binary':
                        if (!$candidate instanceof BinaryCurve) {
                            break;
                        }
                        if ($candidate->getModulo() != $curve->getModulo()) {
                            break;
                        }
                        if ($candidate->getA()->toBytes() != $curve->getA()->toBytes()) {
                            break;
                        }
                        if ($candidate->getB()->toBytes() != $curve->getB()->toBytes()) {
                            break;
                        }

                        [$candidateX, $candidateY] = $candidate->getBasePoint();
                        [$curveX, $curveY] = $curve->getBasePoint();
                        if ($candidateX->toBytes() != $curveX->toBytes()) {
                            break;
                        }
                        if ($candidateY->toBytes() != $curveY->toBytes()) {
                            break;
                        }

                        return $returnArray ?
                            ['namedCurve' => $testName] :
                            ASN1::encodeDER(['namedCurve' => $testName], Maps\ECParameters::MAP);
                }
            }
        }

        $order = $curve->getOrder();
        // we could try to calculate the order thusly:
        // https://crypto.stackexchange.com/a/27914/4520
        // https://en.wikipedia.org/wiki/Schoof%E2%80%93Elkies%E2%80%93Atkin_algorithm
        if (!$order) {
            throw new RuntimeException('Specified Curves need the order to be specified');
        }
        $point = $curve->getBasePoint();
        $x = $point[0]->toBytes();
        $y = $point[1]->toBytes();

        if ($curve instanceof PrimeCurve) {
            /*
             * valid versions are:
             *
             * ecdpVer1:
             *   - neither the curve or the base point are generated verifiably randomly.
             * ecdpVer2:
             *   - curve and base point are generated verifiably at random and curve.seed is present
             * ecdpVer3:
             *   - base point is generated verifiably at random but curve is not. curve.seed is present
             */
            // other (optional) parameters can be calculated using the methods discused at
            // https://crypto.stackexchange.com/q/28947/4520
            $data = [
                'version' => 'ecdpVer1',
                'fieldID' => [
                    'fieldType' => 'prime-field',
                    'parameters' => $curve->getModulo(),
                ],
                'curve' => [
                    'a' => $curve->getA()->toBytes(),
                    'b' => $curve->getB()->toBytes(),
                ],
                'base' => "\4" . $x . $y,
                'order' => $order,
            ];

            return $returnArray ?
                ['specifiedCurve' => $data] :
                ASN1::encodeDER(['specifiedCurve' => $data], Maps\ECParameters::MAP);
        }
        if ($curve instanceof BinaryCurve) {
            $modulo = $curve->getModulo();
            $basis = count($modulo);
            $m = array_shift($modulo);
            array_pop($modulo); // the last parameter should always be 0
            //rsort($modulo);
            switch ($basis) {
                case 3:
                    $basis = 'tpBasis';
                    $modulo = new BigInteger($modulo[0]);
                    break;
                case 5:
                    $basis = 'ppBasis';
                    // these should be in strictly ascending order (hence the commented out rsort above)
                    $modulo = [
                        'k1' => new BigInteger($modulo[2]),
                        'k2' => new BigInteger($modulo[1]),
                        'k3' => new BigInteger($modulo[0]),
                    ];
                    $modulo = ASN1::encodeDER($modulo, Maps\Pentanomial::MAP);
                    $modulo = new ASN1\Element($modulo);
            }
            $params = ASN1::encodeDER([
                'm' => new BigInteger($m),
                'basis' => $basis,
                'parameters' => $modulo,
            ], Maps\Characteristic_two::MAP);
            $params = new ASN1\Element($params);
            $a = ltrim($curve->getA()->toBytes(), "\0");
            if (!strlen($a)) {
                $a = "\0";
            }
            $b = ltrim($curve->getB()->toBytes(), "\0");
            if (!strlen($b)) {
                $b = "\0";
            }
            $data = [
                'version' => 'ecdpVer1',
                'fieldID' => [
                    'fieldType' => 'characteristic-two-field',
                    'parameters' => $params,
                ],
                'curve' => [
                    'a' => $a,
                    'b' => $b,
                ],
                'base' => "\4" . $x . $y,
                'order' => $order,
            ];

            return $returnArray ?
                ['specifiedCurve' => $data] :
                ASN1::encodeDER(['specifiedCurve' => $data], Maps\ECParameters::MAP);
        }

        throw new UnsupportedCurveException('Curve cannot be serialized');
    }

    /**
     * Use Specified Curve
     *
     * A specified curve has all the coefficients, the base points, etc, explicitely included.
     * A specified curve is a more verbose way of representing a curve
     */
    public static function useSpecifiedCurve(): void
    {
        self::$useNamedCurves = false;
    }

    /**
     * Use Named Curve
     *
     * A named curve does not include any parameters. It is up to the EC parameters to
     * know what the coefficients, the base points, etc, are from the name of the curve.
     * A named curve is a more concise way of representing a curve
     */
    public static function useNamedCurve(): void
    {
        self::$useNamedCurves = true;
    }
}
