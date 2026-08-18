<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\File\X509;

use phpseclib4\Crypt\EC;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Maps\LogotypeExtn;
use phpseclib4\File\X509;
use phpseclib4\Tests\PhpseclibTestCase;

class LogotypeTest extends PhpseclibTestCase
{
    /**
     * SHA-1 over a single 0x01 octet - the value is irrelevant to the mapping,
     * it just has to be a well formed HashAlgAndValue
     */
    private const HASH = [
        'hashAlg' => ['algorithm' => 'id-sha1'],
        'hashValue' => "\x01",
    ];

    private const DETAILS = [
        'mediaType' => 'image/svg+xml',
        'logotypeHash' => [self::HASH],
        'logotypeURI' => ['https://example.com/logo.svg'],
    ];

    /** @psalm-suppress InvalidReturnType, InvalidReturnStatement */
    private static function roundtrip(array $value): \phpseclib4\File\ASN1\Types\BaseType
    {
        $der = ASN1::encodeDER($value, LogotypeExtn::MAP);

        return ASN1::map(ASN1::decodeBER($der), LogotypeExtn::MAP);
    }

    /**
     * the extension is wired up in the Extension trait, so it has to survive a
     * trip through an actual certificate - not just through the map.
     *
     * the criticality argument is deliberately omitted so that the default from
     * getExtensionCriticalValue() is what gets exercised - RFC 9399, section 4.1
     * says the extension MUST NOT be marked critical
     */
    public function testExtensionInCertificate(): void
    {
        $key = EC::createKey('ed25519');

        $cert = new X509($key->getPublicKey());
        $cert->addDNProp('id-at-organizationName', 'phpseclib logotype test');
        $cert->makeCA();
        $cert->setExtension(
            'id-pe-logotype',
            ['subjectLogo' => ['direct' => ['image' => [['imageDetails' => self::DETAILS]]]]]
        );
        $key->sign($cert);

        $value = null;
        $critical = null;
        foreach (X509::load("$cert")['tbsCertificate']['extensions'] as $extension) {
            if ("$extension[extnId]" === 'id-pe-logotype') {
                $value = $extension['extnValue'];
                $critical = $extension['critical'];
            }
        }

        $this->assertNotNull($value);
        $this->assertFalse($critical->value);
        $this->assertSame(['subjectLogo'], $value->keys());
        $this->assertSame('direct', $value['subjectLogo']->index);
        $this->assertSame(
            'image/svg+xml',
            (string) $value['subjectLogo']['direct']['image'][0]['imageDetails']['mediaType']
        );
    }

    /**
     * LogotypeImageInfo with every optional field populated, including the
     * resolution CHOICE and the [4] language tag
     */
    public function testImageWithFullImageInfo(): void
    {
        $result = self::roundtrip(['subjectLogo' => ['direct' => ['image' => [[
            'imageDetails' => self::DETAILS,
            'imageInfo' => [
                'type' => 'grayScale',
                'fileSize' => 12345,
                'xSize' => 100,
                'ySize' => 50,
                'resolution' => ['numBits' => 8],
                'language' => 'de',
            ],
        ]]]]]);

        $info = $result['subjectLogo']['direct']['image'][0]['imageInfo'];

        $this->assertSame('grayScale', (string) $info['type']);
        $this->assertSame('12345', (string) $info['fileSize']);
        $this->assertSame('100', (string) $info['xSize']);
        $this->assertSame('50', (string) $info['ySize']);
        $this->assertSame('numBits', $info['resolution']->index);
        $this->assertSame('8', (string) $info['resolution']['numBits']);
        $this->assertSame('de', (string) $info['language']);
    }

    /**
     * the other arm of the resolution CHOICE
     */
    public function testImageResolutionTableSize(): void
    {
        $result = self::roundtrip(['subjectLogo' => ['direct' => ['image' => [[
            'imageDetails' => self::DETAILS,
            'imageInfo' => [
                'fileSize' => 0,
                'xSize' => 0,
                'ySize' => 0,
                'resolution' => ['tableSize' => 256],
            ],
        ]]]]]);

        $resolution = $result['subjectLogo']['direct']['image'][0]['imageInfo']['resolution'];

        $this->assertSame('tableSize', $resolution->index);
        $this->assertSame('256', (string) $resolution['tableSize']);
    }

    /**
     * audio is [1] within LogotypeData and carries its own info structure
     */
    public function testAudio(): void
    {
        $result = self::roundtrip(['subjectLogo' => ['direct' => ['audio' => [[
            'audioDetails' => ['mediaType' => 'audio/mpeg'] + self::DETAILS,
            'audioInfo' => [
                'fileSize' => 10,
                'playTime' => 20,
                'channels' => 2,
                'sampleRate' => 44100,
                'language' => 'en',
            ],
        ]]]]]);

        $audio = $result['subjectLogo']['direct']['audio'][0];

        $this->assertSame('audio/mpeg', (string) $audio['audioDetails']['mediaType']);
        $this->assertSame('20', (string) $audio['audioInfo']['playTime']);
        $this->assertSame('2', (string) $audio['audioInfo']['channels']);
        $this->assertSame('44100', (string) $audio['audioInfo']['sampleRate']);
        $this->assertSame('en', (string) $audio['audioInfo']['language']);
    }

    /**
     * the indirect arm of LogotypeInfo, ie. a LogotypeReference
     */
    public function testIndirect(): void
    {
        $result = self::roundtrip(['issuerLogo' => ['indirect' => [
            'refStructHash' => [self::HASH],
            'refStructURI' => ['https://example.com/logotypes'],
        ]]]);

        $this->assertSame('indirect', $result['issuerLogo']->index);
        $this->assertSame(
            'https://example.com/logotypes',
            (string) $result['issuerLogo']['indirect']['refStructURI'][0]
        );
    }

    /**
     * communityLogos is [0] EXPLICIT around a SEQUENCE OF, not around a single logo
     */
    public function testCommunityLogos(): void
    {
        $logo = ['direct' => ['image' => [['imageDetails' => self::DETAILS]]]];

        $result = self::roundtrip(['communityLogos' => [$logo, $logo]]);

        $this->assertCount(2, $result['communityLogos']);
        $this->assertSame('direct', $result['communityLogos'][0]->index);
    }

    /**
     * otherLogos pairs a logotype type OID with a LogotypeInfo
     */
    public function testOtherLogos(): void
    {
        $result = self::roundtrip(['otherLogos' => [[
            'logotypeType' => 'id-logo-certImage',
            'info' => ['direct' => ['image' => [['imageDetails' => self::DETAILS]]]],
        ]]]);

        $this->assertSame('id-logo-certImage', (string) $result['otherLogos'][0]['logotypeType']);
        $this->assertSame('direct', $result['otherLogos'][0]['info']->index);
    }

    /**
     * all four slots at once - communityLogos and otherLogos are SEQUENCE OF,
     * issuerLogo and subjectLogo are single logos
     */
    public function testAllFourSlots(): void
    {
        $logo = ['direct' => ['image' => [['imageDetails' => self::DETAILS]]]];

        $result = self::roundtrip([
            'communityLogos' => [$logo],
            'issuerLogo' => $logo,
            'subjectLogo' => $logo,
            'otherLogos' => [['logotypeType' => 'id-logo-loyalty', 'info' => $logo]],
        ]);

        $this->assertSame(
            ['communityLogos', 'issuerLogo', 'subjectLogo', 'otherLogos'],
            $result->keys()
        );
    }

    /**
     * issuerLogo [1] and subjectLogo [2] share the same CHOICE definition, so only
     * the context tag tells them apart. the two vectors below are byte for byte
     * identical apart from that tag. before the tagged CHOICE fix every real world
     * BIMI certificate - all of which carry their logo in subjectLogo - was reported
     * as issuerLogo.
     */
    public function testSubjectLogoIsNotConfusedWithIssuerLogo(): void
    {
        // SEQUENCE { [2] EXPLICIT { [0] { SEQUENCE OF { SEQUENCE { LogotypeDetails } } } } }
        $subject = "0\x22\xa2\x20\xa0\x1e0\x1c0\x1a0\x18\x16\x01i0\x0e0\x0c0\x07" .
                   "\x06\x05\x2b\x0e\x03\x02\x1a\x04\x01\x010\x03\x16\x01u";
        $issuer = $subject;
        $issuer[2] = "\xa1";

        $this->assertSame(
            ['subjectLogo'],
            ASN1::map(ASN1::decodeBER($subject), LogotypeExtn::MAP)->keys()
        );
        $this->assertSame(
            ['issuerLogo'],
            ASN1::map(ASN1::decodeBER($issuer), LogotypeExtn::MAP)->keys()
        );
    }

    /**
     * type is DEFAULT color, so an absent [0] has to read back as color and
     * encoding color again must not put it back on the wire
     */
    public function testImageTypeDefaultsToColor(): void
    {
        // ...same as above but with an imageInfo of { INTEGER 0, INTEGER 1, INTEGER 2 }
        $der = "0-\xa2\x2b\xa0\x290\x270\x250\x18\x16\x01i0\x0e0\x0c0\x07" .
               "\x06\x05\x2b\x0e\x03\x02\x1a\x04\x01\x010\x03\x16\x01u" .
               "0\x09\x02\x01\x00\x02\x01\x01\x02\x01\x02";

        $result = ASN1::map(ASN1::decodeBER($der), LogotypeExtn::MAP);
        $info = $result['subjectLogo']['direct']['image'][0]['imageInfo'];

        $this->assertSame('color', (string) $info['type']);

        $reencoded = ASN1::encodeDER([
            'subjectLogo' => ['direct' => ['image' => [[
                'imageDetails' => [
                    'mediaType' => 'i',
                    'logotypeHash' => [self::HASH],
                    'logotypeURI' => ['u'],
                ],
                'imageInfo' => ['type' => 'color', 'fileSize' => 0, 'xSize' => 1, 'ySize' => 2],
            ]]]],
        ], LogotypeExtn::MAP);

        $this->assertSame($der, $reencoded);
    }

    /**
     * Verified Mark Certificates, fetched on 2026-08-08 from the BIMI DNS records
     * of the domains below. BIMI is what puts a sender's logo beside their mail,
     * and these certificates are what backs that logo with a registered trademark
     * - in practice the only place the logotype extension turns up in quantity.
     *
     * three different issuing CAs, so the structure is not one vendor's habit:
     *
     *   vmc-ebay.pem      ebay.com     DigiCert Verified Mark RSA4096 SHA256 2021 CA1
     *   vmc-badoo.pem     badoo.com    Sectigo Limited VMC Issuing RSA CA 1
     *   vmc-rabobank.pem  rabobank.nl  DigiCert Verified Mark Europe RSA4096 SHA256 2023 CA1
     *
     * deliberately no assertion on the validity dates - these expire in 2027 and
     * the test should not go red when they do.
     */
    public function testRealWorldCertificates(): void
    {
        foreach (['vmc-ebay.pem', 'vmc-badoo.pem', 'vmc-rabobank.pem'] as $file) {
            $pem = file_get_contents(__DIR__ . '/' . $file);
            $cert = X509::load($pem);

            $extension = null;
            foreach ($cert['tbsCertificate']['extensions'] as $candidate) {
                if ("$candidate[extnId]" === 'id-pe-logotype') {
                    $extension = $candidate;
                }
            }

            $this->assertNotNull($extension, $file);
            // "This extension MUST NOT be marked critical" - RFC 9399, section 4.1
            $this->assertFalse($extension['critical']->value, $file);

            $value = $extension['extnValue'];

            // every one of these puts its logo in subjectLogo. before tagged CHOICE
            // children were matched on their own tag they all came back as issuerLogo
            $this->assertSame(['subjectLogo'], $value->keys(), $file);
            $this->assertSame('direct', $value['subjectLogo']->index, $file);

            $details = $value['subjectLogo']['direct']['image'][0]['imageDetails'];
            $this->assertSame('image/svg+xml', (string) $details['mediaType'], $file);

            // the logo is embedded rather than linked, and gzipped, as RFC 9399
            // section 7 requires of SVG carried in a data URL
            $uri = (string) $details['logotypeURI'][0];
            $this->assertStringStartsWith('data:image/svg+xml;base64,', $uri, $file);
            $this->assertStringContainsString(
                '<svg',
                (string) gzdecode(base64_decode(explode(',', $uri, 2)[1])),
                $file
            );

            $this->assertNotEmpty("$details[logotypeHash][0][hashValue]", $file);

            // and the whole certificate survives a round trip untouched
            $this->assertSame(
                bin2hex((string) base64_decode(preg_replace('#-.*-|\s#', '', $pem))),
                bin2hex((string) base64_decode(preg_replace('#-.*-|\s#', '', (string) $cert))),
                $file
            );
        }
    }

    /**
     * the BIMI mark attributes in these certificates' subject DNs, which without
     * their OIDs registered come out as bare numbers. only the four below appear
     * in real certificates I could find - wordMark, legalEntityIdentifier and the
     * statute* attributes are specified but do not seem to be issued anywhere.
     */
    public function testMarkAttributesInSubjectDN(): void
    {
        $expected = [
            'vmc-ebay.pem' => [
                'markType = Registered Mark',
                'trademarkCountryOrRegionName = US',
                'trademarkRegistration = 4408423',
            ],
            'vmc-badoo.pem' => [
                'trademarkOfficeName = Intellectual Property Office',
                'trademarkCountryOrRegionName = GB',
                'trademarkRegistration = UK00004062752',
            ],
        ];

        foreach ($expected as $file => $attributes) {
            $dn = X509::load(file_get_contents(__DIR__ . '/' . $file))
                ->getSubjectDN(X509::DN_STRING);

            foreach ($attributes as $attribute) {
                $this->assertStringContainsString($attribute, $dn, $file);
            }

            $this->assertStringNotContainsString('1.3.6.1.4.1.53087', $dn, $file);
        }
    }

    /**
     * the VMC policy identifier, which every Verified Mark Certificate asserts
     * next to the issuing CA's own policy. it is a certificate policy rather
     * than a DN attribute, hence certificatePolicies instead of the subject DN
     */
    public function testPolicyIdentifierInCertificatePolicies(): void
    {
        foreach (['vmc-ebay.pem', 'vmc-badoo.pem', 'vmc-rabobank.pem'] as $file) {
            $cert = X509::load(file_get_contents(__DIR__ . '/' . $file));

            $policies = [];
            foreach ($cert['tbsCertificate']['extensions'] as $extension) {
                if ("$extension[extnId]" !== 'id-ce-certificatePolicies') {
                    continue;
                }

                foreach ($extension['extnValue'] as $policy) {
                    $policies[] = "$policy[policyIdentifier]";
                }
            }

            $this->assertContains('certificateGeneralPolicyIdentifier', $policies, $file);
        }
    }
}
