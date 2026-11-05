# ML-DSA fixtures

Made with the OpenSSL 4.0.3 command line tool, except `null-params-ML-DSA-44.pem` (see the end). Used by
`tests/Unit/File/X509/MLDSATest.php` and `tests/Unit/File/CMS/MLDSATest.php`.

| File | What it is |
|---|---|
| `key-ML-DSA-{44,65,87}.pem` | seed-only private keys (RFC 9881, the `seed` CHOICE) |
| `self-signed-ML-DSA-{44,65,87}.pem` | self-signed CA certificates, one per parameter set, 10 years |
| `csr-ML-DSA-44.pem` | CSR for the leaf, signed with `key-ML-DSA-44.pem` |
| `leaf-ML-DSA-44.pem` | the CSR issued by the ML-DSA-65 certificate (an ML-DSA-44 key, an ML-DSA-65 signature) |
| `crl-ML-DSA-65.pem` | CRL of the ML-DSA-65 certificate, with the leaf revoked (keyCompromise) |
| `cms-ML-DSA-44.pem` | CMS SignedData by the leaf, content attached, digest SHA-512 |
| `null-params-ML-DSA-44.pem` | negative: the ML-DSA-44 self-signed certificate with a NULL in both AlgorithmIdentifiers |

## Commands

```sh
for n in 44 65 87; do
  openssl genpkey -algorithm ML-DSA-$n -provparam ml-dsa.output_formats=seed-only -out key-ML-DSA-$n.pem
  openssl req -x509 -new -key key-ML-DSA-$n.pem -subj "/O=phpseclib ML-DSA-$n self-signed" -days 3650 \
    -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign" -addext "basicConstraints=critical,CA:TRUE" \
    -out self-signed-ML-DSA-$n.pem
done

openssl req -new -key key-ML-DSA-44.pem -subj "/CN=phpseclib ML-DSA-44 leaf" \
  -addext "keyUsage=critical,digitalSignature" -out csr-ML-DSA-44.pem

# the leaf and the CRL come from openssl ca, with this configuration (cadb is an empty
# directory with an empty index.txt, serial = 1000 and crlnumber = 01)
cat > ca.cnf <<'CNF'
[ ca ]
default_ca = ca_default
[ ca_default ]
dir = ./cadb
database = $dir/index.txt
new_certs_dir = $dir
serial = $dir/serial
crlnumber = $dir/crlnumber
default_days = 3650
default_crl_days = 3650
default_md = default
policy = policy_any
copy_extensions = copy
x509_extensions = leaf_ext
unique_subject = no
[ policy_any ]
commonName = optional
organizationName = optional
[ leaf_ext ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF
openssl ca -config ca.cnf -batch -notext -keyfile key-ML-DSA-65.pem -cert self-signed-ML-DSA-65.pem \
  -in csr-ML-DSA-44.pem -out leaf-ML-DSA-44.pem
openssl ca -config ca.cnf -keyfile key-ML-DSA-65.pem -cert self-signed-ML-DSA-65.pem \
  -revoke leaf-ML-DSA-44.pem -crl_reason keyCompromise
openssl ca -config ca.cnf -keyfile key-ML-DSA-65.pem -cert self-signed-ML-DSA-65.pem -gencrl -out crl-ML-DSA-65.pem

# SHA-512 is given because OpenSSL picks SHAKE256 for ML-DSA by default and the
# SignedData parser doesn't know id-shake256
printf 'ML-DSA in CMS: signed by the ML-DSA-44 leaf, digest SHA-512\n' > cms-message.txt
openssl cms -sign -in cms-message.txt -signer leaf-ML-DSA-44.pem -inkey key-ML-DSA-44.pem \
  -md sha512 -binary -nodetach -nosmimecap -outform PEM -out cms-ML-DSA-44.pem
```

Checked with the same tool:

```sh
openssl verify -CAfile self-signed-ML-DSA-44.pem self-signed-ML-DSA-44.pem      # OK (same for 65 and 87)
openssl req -in csr-ML-DSA-44.pem -verify -noout                                 # verify OK
openssl verify -CAfile self-signed-ML-DSA-65.pem leaf-ML-DSA-44.pem              # OK
openssl crl -in crl-ML-DSA-65.pem -CAfile self-signed-ML-DSA-65.pem -verify -noout   # verify OK
openssl verify -CAfile self-signed-ML-DSA-65.pem -crl_check -CRLfile crl-ML-DSA-65.pem leaf-ML-DSA-44.pem   # certificate revoked
openssl cms -verify -binary -in cms-ML-DSA-44.pem -inform PEM -CAfile self-signed-ML-DSA-65.pem -out cms-verified.txt   # successful
```

## null-params-ML-DSA-44.pem

RFC 9881, section 3, says the parameters of the signature AlgorithmIdentifier must be absent. This file is
`self-signed-ML-DSA-44.pem` with an explicit NULL in `tbsCertificate.signature` and in `signatureAlgorithm`,
re-signed with `key-ML-DSA-44.pem` so that the NULLs are the only thing wrong with it:

```php
$private = MLDSA::loadPrivateKey(file_get_contents('key-ML-DSA-44.pem'));
$x509 = X509::load(file_get_contents('self-signed-ML-DSA-44.pem'));
$x509['tbsCertificate']['signature']['parameters'] = new ExplicitNull();
$x509['signatureAlgorithm']['parameters'] = new ExplicitNull();
$x509->setSignature($private->sign($x509->getSignableSection()));
file_put_contents('null-params-ML-DSA-44.pem', "$x509");
```

`openssl verify -CAfile null-params-ML-DSA-44.pem null-params-ML-DSA-44.pem` says OK: OpenSSL 4.0.3 doesn't
check the parameters. phpseclib rejects the certificate.
