<?php

declare(strict_types=1);

namespace phpseclib3\Crypt;

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\DILITHIUM\PrivateKey;
use phpseclib3\Crypt\DILITHIUM\PublicKey;
use phpseclib3\Exception\UnsupportedAlgorithmException;

abstract class DILITHIUM extends AsymmetricKey
{
    public const ALGORITHM = 'DILITHIUM';

    protected string $pem;
    protected string $raw_bit_string;
    protected string $method_name;

    protected function __construct()
    {
        parent::__construct();
        $this->hash = new Hash('sha512');

        exec(
            "openssl list -providers",
            $output,
            $return
        );
        $has_oqsprovider = array_search('oqsprovider', array_map('trim', $output)) !== false;

        // set proper engine
        self::$engines = [
            'oqsphp' => extension_loaded('oqsphp'),
            'PQC-OpenSSL' => $has_oqsprovider
        ];
    }

    protected static function onLoad(array $components)
    {
        $key = $components['isPublicKey'] ?
            new PublicKey() :
            new PrivateKey();

        $key->method_name = $components['method_name'];
        $key->pem = $components['pem'];
        $key->raw_bit_string = $components['raw'];

        return $key;
    }

    public function withHash(string $hash): AsymmetricKey
    {
        if ($hash != 'sha512') {
            throw new UnsupportedAlgorithmException('Post-quantum algorithm only supports sha512 as a hash');
        }

        return parent::withHash($hash);
    }
}
