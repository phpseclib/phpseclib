<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2013 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\DSA;
use phpseclib\Crypt\DSA\Keys\PKCS1;
use phpseclib\Crypt\DSA\Keys\PKCS8;
use phpseclib\Crypt\DSA\Keys\PuTTY;
use phpseclib\Math\BigInteger;

class Unit_Crypt_DSA_LoadKeyTest extends PhpseclibTestCase
{
    public function testBadKey()
    {
        $dsa = new DSA();

        $key = 'zzzzzzzzzzzzzz';

        $this->assertFalse($dsa->load($key));
    }
    public function testPuTTYKey()
    {
        $dsa = new DSA();

        $key = 'PuTTY-User-Key-File-2: ssh-dss
Encryption: none
Comment: dsa-key-20161223
Public-Lines: 18
AAAAB3NzaC1kc3MAAAEBAIsH1A8S7goEEneW6D/zJXh1zypZRlKlw7vNaJ7yXi9v
qUkKnTSXK9lR4/nYy4SVTcVApY0sEU2RSDridLTy40ZeMPArH+sxR7lCSZ2AuNq9
sQxu6VtYg1LKGekKYWC+r4TrZoTz2PUyrUd6sYBsYIX4ozbH2ITgYmYL9ONCrLbt
4KsKO2EUE3xN3RHv8CkAp5BraCMw5z4vC43t0bcW63RN2mEvqWOqBFx5qe7uck4j
pH7AvLyvwEye7t5KwJ8P1SMN72u4AWqyXqzLK3Ye0B7hQSFnbz0od4ps3EN+Irsu
Kf20nkGgHKYJwenpIQwHz3xhBhtgiYCdQXb3ril1kd8AAAAVAJmhajsmmqwQqNkd
k4JSJ/Y1SE11AAABADYHKKmAZ0OvCZ58m5CGPfuoX4h4nc5L0p3e0Sozcc9cJ5h3
PvD18ggAf4cLoTpxETnXTFg+30shpKbr2WsE0Jrswe6V2bMaP7Hil6q3WWahLZx6
9bEClnYCTlJkungzFjJmW+M7yd8xBHCBM6r83FKlLJjolJhHDL5DqX/uHP/9H0sl
wncwALro1jTo3JU5oRdzMuLWf9P2MB7sEsoeWk2BOiil1BtKnItuObJgXUCCuaWB
dPJyk4ZVMZZqr+vCnjocRrlQUwlMUG73Ze6KJKM1OgOKMt4PwaqD9oUaKq/gc+Eb
UtCwVR6TEeIEkmazguvbAb6dSJ18TMZ07H6DJngAAAEAYE/7gKVb8P23zYzcfYOv
3zG713/i/LAJ+dW3lQupyWkUnE8wDIht7DwKgcA/Vs73jG7SlqPjcMrNzBHjQE+y
FVCP4xO+wDsh2wZ+KVppVkMljfGpp/0mQ0mQbrmTkaCNZc0ogXwtaI4r7Su2cCq0
HMwrFJFFXXLaTZY49+lkrtP6q8WFOYJGK3WnrWvXyOe9Xnh2o8E1dQJ0RnshdOft
j1KZ4JhOHnGKoz8+sKuchGVhs5VaMbJUur3cC8INaeKvtrEpwW/Ety5iy1iPyps9
S9PlwN0KyVFGWdP2B4Gyj85IXCm3r+JNVoV5tVX9IUBTXnUor7YfWNncwWn56Lc+
RQ==
Private-Lines: 1
AAAAFFMy7BG9rPXwzqZzIY/lqsHEILNf
Private-MAC: 62b92ddd8b341b9414d640c24ba6ae929a78e039
';

        $dsa->setPrivateKeyFormat('PuTTY');
        $dsa->setPublicKeyFormat('PuTTY');

        $this->assertTrue($dsa->load($key));
        $this->assertInternalType('string', "$dsa");
        $this->assertSame("$dsa", $dsa->getPrivateKey('PuTTY'));
        $this->assertInternalType('string', $dsa->getPublicKey('PuTTY'));
        $this->assertInternalType('string', $dsa->getParameters());

        $dsa->setPassword('password');
        $this->assertGreaterThan(0, strlen("$dsa"));
    }

    public function testPKCS1Key()
    {
        $dsa = new DSA();

        $key = '-----BEGIN DSA PRIVATE KEY-----
MIIDPQIBAAKCAQEAiwfUDxLuCgQSd5boP/MleHXPKllGUqXDu81onvJeL2+pSQqd
NJcr2VHj+djLhJVNxUCljSwRTZFIOuJ0tPLjRl4w8Csf6zFHuUJJnYC42r2xDG7p
W1iDUsoZ6QphYL6vhOtmhPPY9TKtR3qxgGxghfijNsfYhOBiZgv040Kstu3gqwo7
YRQTfE3dEe/wKQCnkGtoIzDnPi8Lje3RtxbrdE3aYS+pY6oEXHmp7u5yTiOkfsC8
vK/ATJ7u3krAnw/VIw3va7gBarJerMsrdh7QHuFBIWdvPSh3imzcQ34iuy4p/bSe
QaAcpgnB6ekhDAfPfGEGG2CJgJ1BdveuKXWR3wIVAJmhajsmmqwQqNkdk4JSJ/Y1
SE11AoIBADYHKKmAZ0OvCZ58m5CGPfuoX4h4nc5L0p3e0Sozcc9cJ5h3PvD18ggA
f4cLoTpxETnXTFg+30shpKbr2WsE0Jrswe6V2bMaP7Hil6q3WWahLZx69bEClnYC
TlJkungzFjJmW+M7yd8xBHCBM6r83FKlLJjolJhHDL5DqX/uHP/9H0slwncwALro
1jTo3JU5oRdzMuLWf9P2MB7sEsoeWk2BOiil1BtKnItuObJgXUCCuaWBdPJyk4ZV
MZZqr+vCnjocRrlQUwlMUG73Ze6KJKM1OgOKMt4PwaqD9oUaKq/gc+EbUtCwVR6T
EeIEkmazguvbAb6dSJ18TMZ07H6DJngCggEAYE/7gKVb8P23zYzcfYOv3zG713/i
/LAJ+dW3lQupyWkUnE8wDIht7DwKgcA/Vs73jG7SlqPjcMrNzBHjQE+yFVCP4xO+
wDsh2wZ+KVppVkMljfGpp/0mQ0mQbrmTkaCNZc0ogXwtaI4r7Su2cCq0HMwrFJFF
XXLaTZY49+lkrtP6q8WFOYJGK3WnrWvXyOe9Xnh2o8E1dQJ0RnshdOftj1KZ4JhO
HnGKoz8+sKuchGVhs5VaMbJUur3cC8INaeKvtrEpwW/Ety5iy1iPyps9S9PlwN0K
yVFGWdP2B4Gyj85IXCm3r+JNVoV5tVX9IUBTXnUor7YfWNncwWn56Lc+RQIUUzLs
Eb2s9fDOpnMhj+WqwcQgs18=
-----END DSA PRIVATE KEY-----';

        $dsa->setPrivateKeyFormat('PKCS1');
        $dsa->setPublicKeyFormat('PKCS1');

        $this->assertTrue($dsa->load($key));
        $this->assertInternalType('string', "$dsa");
        $this->assertSame("$dsa", $dsa->getPrivateKey('PKCS1'));
        $this->assertInternalType('string', $dsa->getPublicKey('PKCS1'));
        $this->assertInternalType('string', $dsa->getParameters());
    }

    public function testParameters()
    {
        $dsa = new DSA();

        $key = '-----BEGIN DSA PARAMETERS-----
MIIBHgKBgQDandMycPZNOEwDXpIDSdFODWOQVO5tlnt38wK0X33TJh4wQdqOSiVF
I+g+X8reP43ag3TEHu5bstrk6Znm7y1htTTvXQVTEwp6X3YHXbJG4Faul3g08Vud
3gzV841wToVCMUinl0EOxMYP/CO9/Kvf66KACtqWITzJYBpwAeUKfwIVAM8e3xO8
aityXVRiQRWeZtOI1yq9AoGAbmA+RzIZrtPx1mC5KzrpwgwgNHbbQBT83qeNKjEh
N+S6A47iI5OVvpxd/ZwjdXoYo7D6RxR+3LNcT64DyYrBEZuzQzHeifaO6lBvDSNf
L1cwyXx0KMaaampd34MzOIHbC44SHY+cE3aVVUsnmt6Ur1nQaVYVszl+AO6m8bPm
4Vg=
-----END DSA PARAMETERS-----';
        $key = str_replace(["\n", "\r"], '', $key);

        $this->assertTrue($dsa->load($key));
        $this->assertSame($key, str_replace(["\n", "\r"], '', "$dsa"));
        $this->assertSame($key, str_replace(["\n", "\r"], '', $dsa->getParameters()));
    }

    public function testPKCS8Public()
    {
        $dsa = new DSA();

        $key = '-----BEGIN PUBLIC KEY-----
MIIBtjCCASsGByqGSM44BAEwggEeAoGBANqd0zJw9k04TANekgNJ0U4NY5BU7m2W
e3fzArRffdMmHjBB2o5KJUUj6D5fyt4/jdqDdMQe7luy2uTpmebvLWG1NO9dBVMT
CnpfdgddskbgVq6XeDTxW53eDNXzjXBOhUIxSKeXQQ7Exg/8I738q9/rooAK2pYh
PMlgGnAB5Qp/AhUAzx7fE7xqK3JdVGJBFZ5m04jXKr0CgYBuYD5HMhmu0/HWYLkr
OunCDCA0dttAFPzep40qMSE35LoDjuIjk5W+nF39nCN1ehijsPpHFH7cs1xPrgPJ
isERm7NDMd6J9o7qUG8NI18vVzDJfHQoxppqal3fgzM4gdsLjhIdj5wTdpVVSyea
3pSvWdBpVhWzOX4A7qbxs+bhWAOBhAACgYBTpSKcKoVKw+hglVClqvqQdNKGC4a+
XC4lOh2221ZrTgy/sN92vT7cdBn4ydHoth6/bD236L/FYfiX4S4mOczPhrv/l/2u
ZpmyOpXM/0opRMIRdmqVW4ardBFNokmlqngwcbaptfRnk9W2cQtx0lmKy6X/vnis
3AElwP86TYgBhw==
-----END PUBLIC KEY-----';

        $this->assertTrue($dsa->load($key));
        $this->assertInternalType('string', "$dsa");
    }

    public function testPKCS8Private()
    {
        $dsa = new DSA();

        $key = '-----BEGIN PRIVATE KEY-----
MIIBSgIBADCCASsGByqGSM44BAEwggEeAoGBANqd0zJw9k04TANekgNJ0U4NY5BU
7m2We3fzArRffdMmHjBB2o5KJUUj6D5fyt4/jdqDdMQe7luy2uTpmebvLWG1NO9d
BVMTCnpfdgddskbgVq6XeDTxW53eDNXzjXBOhUIxSKeXQQ7Exg/8I738q9/rooAK
2pYhPMlgGnAB5Qp/AhUAzx7fE7xqK3JdVGJBFZ5m04jXKr0CgYBuYD5HMhmu0/HW
YLkrOunCDCA0dttAFPzep40qMSE35LoDjuIjk5W+nF39nCN1ehijsPpHFH7cs1xP
rgPJisERm7NDMd6J9o7qUG8NI18vVzDJfHQoxppqal3fgzM4gdsLjhIdj5wTdpVV
Syea3pSvWdBpVhWzOX4A7qbxs+bhWAQWAhQiF7sFfCtZ7oOgCb2aJ9ySC9sTug==
-----END PRIVATE KEY-----';

        $this->assertTrue($dsa->load($key));
        $this->assertInternalType('string', "$dsa");
        $this->assertSame("$dsa", $dsa->getPrivateKey());
        $this->assertInstanceOf(DSA::class, $dsa->getPublicKey());
        $this->assertInternalType('string', $dsa->getParameters());
    }

    /**
     * @expectedException \UnexpectedValueException
     */
    public function testPuTTYBadMAC()
    {
        $dsa = new DSA();

        $key = 'PuTTY-User-Key-File-2: ssh-dss
Encryption: none
Comment: dsa-key-20161223
Public-Lines: 18
AAAAB3NzaC1kc3MAAAEBAIsH1A8S7goEEneW6D/zJXh1zypZRlKlw7vNaJ7yXi9v
qUkKnTSXK9lR4/nYy4SVTcVApY0sEU2RSDridLTy40ZeMPArH+sxR7lCSZ2AuNq9
sQxu6VtYg1LKGekKYWC+r4TrZoTz2PUyrUd6sYBsYIX4ozbH2ITgYmYL9ONCrLbt
4KsKO2EUE3xN3RHv8CkAp5BraCMw5z4vC43t0bcW63RN2mEvqWOqBFx5qe7uck4j
pH7AvLyvwEye7t5KwJ8P1SMN72u4AWqyXqzLK3Ye0B7hQSFnbz0od4ps3EN+Irsu
Kf20nkGgHKYJwenpIQwHz3xhBhtgiYCdQXb3ril1kd8AAAAVAJmhajsmmqwQqNkd
k4JSJ/Y1SE11AAABADYHKKmAZ0OvCZ58m5CGPfuoX4h4nc5L0p3e0Sozcc9cJ5h3
PvD18ggAf4cLoTpxETnXTFg+30shpKbr2WsE0Jrswe6V2bMaP7Hil6q3WWahLZx6
9bEClnYCTlJkungzFjJmW+M7yd8xBHCBM6r83FKlLJjolJhHDL5DqX/uHP/9H0sl
wncwALro1jTo3JU5oRdzMuLWf9P2MB7sEsoeWk2BOiil1BtKnItuObJgXUCCuaWB
dPJyk4ZVMZZqr+vCnjocRrlQUwlMUG73Ze6KJKM1OgOKMt4PwaqD9oUaKq/gc+Eb
UtCwVR6TEeIEkmazguvbAb6dSJ18TMZ07H6DJngAAAEAYE/7gKVb8P23zYzcfYOv
3zG713/i/LAJ+dW3lQupyWkUnE8wDIht7DwKgcA/Vs73jG7SlqPjcMrNzBHjQE+y
FVCP4xO+wDsh2wZ+KVppVkMljfGpp/0mQ0mQbrmTkaCNZc0ogXwtaI4r7Su2cCq0
HMwrFJFFXXLaTZY49+lkrtP6q8WFOYJGK3WnrWvXyOe9Xnh2o8E1dQJ0RnshdOft
j1KZ4JhOHnGKoz8+sKuchGVhs5VaMbJUur3cC8INaeKvtrEpwW/Ety5iy1iPyps9
S9PlwN0KyVFGWdP2B4Gyj85IXCm3r+JNVoV5tVX9IUBTXnUor7YfWNncwWn56Lc+
RQ==
Private-Lines: 1
AAAAFFMy7BG9rPXwzqZzIY/lqsHEILNf
Private-MAC: aaaaaadd8b341b9414d640c24ba6ae929a78e039
';

        $this->assertFalse($dsa->load($key));
        $dsa->load($key, 'PuTTY');
    }

    public function testXML()
    {
        $dsa = new DSA();

        $key = '-----BEGIN PUBLIC KEY-----
MIIBtjCCASsGByqGSM44BAEwggEeAoGBANqd0zJw9k04TANekgNJ0U4NY5BU7m2W
e3fzArRffdMmHjBB2o5KJUUj6D5fyt4/jdqDdMQe7luy2uTpmebvLWG1NO9dBVMT
CnpfdgddskbgVq6XeDTxW53eDNXzjXBOhUIxSKeXQQ7Exg/8I738q9/rooAK2pYh
PMlgGnAB5Qp/AhUAzx7fE7xqK3JdVGJBFZ5m04jXKr0CgYBuYD5HMhmu0/HWYLkr
OunCDCA0dttAFPzep40qMSE35LoDjuIjk5W+nF39nCN1ehijsPpHFH7cs1xPrgPJ
isERm7NDMd6J9o7qUG8NI18vVzDJfHQoxppqal3fgzM4gdsLjhIdj5wTdpVVSyea
3pSvWdBpVhWzOX4A7qbxs+bhWAOBhAACgYBTpSKcKoVKw+hglVClqvqQdNKGC4a+
XC4lOh2221ZrTgy/sN92vT7cdBn4ydHoth6/bD236L/FYfiX4S4mOczPhrv/l/2u
ZpmyOpXM/0opRMIRdmqVW4ardBFNokmlqngwcbaptfRnk9W2cQtx0lmKy6X/vnis
3AElwP86TYgBhw==
-----END PUBLIC KEY-----';

        $dsa->load($key);
        $xml = $dsa->getPublicKey('XML');
        $this->assertContains('DSAKeyValue', $xml);

        $dsa = new DSA();
        $dsa->load($xml);
        $pkcs8 = $dsa->getPublicKey('PKCS8');

        $this->assertSame(
            strtolower(preg_replace('#\s#', '', $pkcs8)),
            strtolower(preg_replace('#\s#', '', $key))
        );
    }
}
