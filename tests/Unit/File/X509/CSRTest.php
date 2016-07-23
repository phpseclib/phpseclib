<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'File/X509.php';
require_once 'Crypt/RSA.php';

class Unit_File_X509_CSRTest extends PhpseclibTestCase
{
    public function testLoadCSR()
    {
        $test = '-----BEGIN CERTIFICATE REQUEST-----
MIIBWzCBxQIBADAeMRwwGgYDVQQKDBNwaHBzZWNsaWIgZGVtbyBjZXJ0MIGdMAsG
CSqGSIb3DQEBAQOBjQAwgYkCgYEAtHDb4zoUyiRYsJ5PZrF/IJKAF9ZoHRpTxMA8
a7iyFdsl/vvZLNPsNnFTXXnGdvsyFDEsF7AubaIXw8UKFPYqQRTzSVsvnNgIoVYj
tTAXlB4oHipr7Kxcn4CXfmR0TYogyLvVZSZJYxh+CAuG4V9XM4HqkeE5gyBOsKGy
5FUU8zMCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA4GBAJjdaA9K9DN5xvSiOlCmmV1E
npzHkI1Trraveu0gtRjT/EzHoqjCBI0ekCZ9+fhrex8Sm6Nsq9IgHYyrqnE+PQko
4Nf2w2U3DWxU26D5E9DlI+bLyOCq4jqATLjHyyAsOZY/2+U73AZ82MJM/mGdh5fQ
v5RwaQHmQEzHofTzF7I+
-----END CERTIFICATE REQUEST-----';

        $x509 = new File_X509();

        $spkac = $x509->loadCSR($test);

        $this->assertInternalType('array', $spkac);
    }

    public function testCSRWithAttributes()
    {
        $test = '-----BEGIN NEW CERTIFICATE REQUEST-----
MIIFGDCCAwACAQAwOjEWMBQGCgmSJomT8ixkARkWBnNlY3VyZTEgMB4GA1UEAxMX
LlNlY3VyZSBFbnRlcnByaXNlIENBIDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
ggIKAoICAQCzgEpL+Za7a3y7YpURDrxlGIBlks25fD0tHaZIYkBTaXA5h+9MWoXn
FA7AlIUt8pbBvXdJbOCmGaeQmBfBH0Qy9vTbx/DR2IOwzqy2ZHuurI5bPL12ceE2
Mxa9xgY/i7U6MAUtoA3amEd7cKj2fz9EWZruRladOX0DXv9KexSan+45QjCWH+u2
Cxem2zH9ZDNPGBuAF9YsAvkdHdAoX8aSm05ZAjUiO2e/+L57whh7zZiDY3WIhin7
N/2JNTKVO6lx50S8a34XUKBt3SKgSR941hcLrBYUNftUYsTPo40bzKKcWqemiH+w
jQiDrln4V2b5EbVeoGWe4UDPXCVmC6UPklG7iYfF0eeK4ujV8uc9PtV2LvGLOFdm
AYE3+FAba5byQATw/DY8EJKQ7ptPigJhVe47NNeJlsKwk1haJ9k8ZazjS+vT45B5
pqe0yBFAEon8TFnOLnAOblmKO12i0zqMUNAAlmr1c8jNjLr+dhruS+QropZmzZ24
mAnFG+Y0qpfhMzAxTGQyVjyGwDfRK/ARmtrGpmROjj5+6VuMmZ6Ljf3xN09epmtH
gJe+lYNBlpfUYg16tm+OusnziYnXL6nIo2ChOY/7GNJJif9fjvvaPDCC98K64av5
5rpIx7N/XH4hwHeQQkEQangExE+8UMyBNFNmvPnIHVHUZdYo4SLsYwIDAQABoIGY
MBsGCisGAQQBgjcNAgMxDRYLNi4zLjk2MDAuMi4weQYJKoZIhvcNAQkOMWwwajAQ
BgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU5nEIMEUT5mMd1WepmviwgK7dIzww
GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAKZl6bAeaID3b/ic4aztL8ZZI7vi
D3A9otUKx6v1Xe63zDPR+DiWSnxb9m+l8OPtnWkcLkzEIM/IMWorHKUAJ/J871D0
Qx+0/HbkcrjMtVu/dNrtb9Z9CXup66ZvxTPcpEziq0/n2yw8QdBaa+lli65Qcwcy
tzMQK6WQTRYfvVCIX9AKcPKxwx1DLH+7hL/bERB1lUDu59Jx6fQfqJrFVOY2N8c0
MGvurfoHGmEoyCMIyvmIMu4+/wSNEE/sSDp4lZ6zuF6rf1m0GiLdTX2XJE+gfvep
JTFmp4S3WFqkszKvaxBIT+jV0XKTNDwnO+dpExwU4jZUh18CdEFkIUuQb0gFF8B7
WJFVpNdsRqZRPBz83BW1Kjo0yAmaoTrGNmG0p6Qf3K2zbk1+Jik3VZq4rvKoTi20
6RvLA2//cMNfkYPsuqvoHGe2e0GOLtIB63wJzloWROpb72ohEHsvCKullIJVSuiS
9sfTBAenHCyndgAEd4T3npTUdaiNumVEm5ilZId7LAYekJhkgFu3vlcl8blBJKjE
skVTp7JpBmdXCL/G/6H2SFjca4JMOAy3DxwlGdgneIaXazHs5nBK/BgKPIyPzZ4w
secxBTTCNgI48YezK3GDkn65cmlnkt6F6Mf0MwoDaXTuB88Jycbwb5ihKnHEJIsO
draiRBZruwMPwPIP
-----END NEW CERTIFICATE REQUEST-----';

        $x509 = new File_X509();

        $csr = $x509->loadCSR($test);

        $this->assertInternalType('array', $csr);
    }

    public function testCSRDER()
    {
        $csr = 'MIICdzCCAV8CAQEwDDEKMAgGA1UEAwwBeDCCASIwDQYJKoZIhvcNAQEBBQADggEP' .
               'ADCCAQoCggEBALtcrFDD2AHe3x2bR00wPDsPH6FJLxr5uc1ybb+ldDB5xNVImC8P' .
               'LU6VXDZ5z68KjSovs1q0OWJWfCjlAuGLzqO35s86LI1CFuTFdkScVHMwh8zUVFoP' .
               'pG7/9rKaNxCgaHs4evxjxQP2+Ny7tBqPLb/KV0exm6Twocf963jC/Tyn57G5erRf' .
               'zpFrfK7DozhxY7znumJ4FuSn0TVkD6PPwZFn9VoTjv2ZoJmacGK+0r5yNKG799F5' .
               'K8EgDrOCfbzCZjX6GJctyn2SNPTeBuXS9piH21FGnJAryv80zG+zUqFdEyoLUGJt' .
               '4Vy6+tDP9cW68fiwTZS1Oc1VeFdL1G/CrjkCAwEAAaAmMCQGCSqGSIb3DQEJDjEX' .
               'MBUwEwYKKwYBBAGCqlsBCQQFMAOCAQEwDQYJKoZIhvcNAQELBQADggEBAF4XOd+1' .
               'jkJOYRInNpHfhzSD/ktDY50gpLPuDvl4f/ZBlKrb1eDYQG5F3bnYzoZWHN4n+6Zs' .
               'CkljXs5ZPUZ5LuVpASumoG/aHXGz8c8NC3asJ1V73ljEPAfIXwqoIUoaP9jLL+Ee' .
               'zy/ZCi2NKWVo2D7ocnn79oblAem9ksSeQl4z3Gvhuug6MsMqn96NU/ZY/vjYzAjb' .
               'MAvJIVRY0rbCxbFa0K+XNJtF7GLyBxyPNFWCvADhvm9C4uPmoypYg7MY6EewJInN' .
               'xzMH7I4xDLjNu0VBa6lAxTvflp0joQHKlTYX0SDIKPbQivjZMuObPuxDtkVZ0rQl' .
               'AjmgMowaN5otTXM=';
        $csr = base64_decode($csr);

        $x509 = new File_X509();

        $csr = $x509->loadCSR($csr);

        $this->assertInternalType('array', $csr);
    }

    // on PHP 7.1, with older versions of phpseclib, this would produce a "A non-numeric value encountered" warning
    public function testNewCSR()
    {
        $rsa = new Crypt_RSA();
        $x509 = new File_X509();

        $rsa->loadKey('-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp
wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5
1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh
3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2
pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX
GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il
AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF
L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k
X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl
U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ
37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=
-----END RSA PRIVATE KEY-----');
        $x509->setPrivateKey($rsa);
        $x509->setDN(array('cn' => 'website.com'));
        $x509->saveCSR($x509->signCSR('sha256WithRSAEncryption'), FILE_X509_FORMAT_DER);
    }
}
