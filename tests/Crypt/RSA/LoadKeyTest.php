<?php
/**
 * @author     Jim Wigginton <terrafrost@php.net>
 * @copyright  MMXIII Jim Wigginton
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Crypt_RSA_LoadKeyTest extends PhpseclibTestCase
{
	public function testPKCS1Key()
	{
		$rsa = new Crypt_RSA();

		$key = '-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----';

		$this->assertTrue($rsa->loadKey($key));
	}

	public function testPKCS1SpacesKey()
	{
		$rsa = new Crypt_RSA();

		$key = '-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----';
		$key = str_replace(array("\r", "\n", "\r\n"), ' ', $key);

		$this->assertTrue($rsa->loadKey($key));
	}

	public function testPKCS1NoHeaderKey()
	{
		$rsa = new Crypt_RSA();

		$key = 'MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp
wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5
1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh
3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2
pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX
GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il
AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF
L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k
X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl
U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ
37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=';

		$this->assertTrue($rsa->loadKey($key));
	}

	public function testPKCS1NoWhitespaceNoHeaderKey()
	{
		$rsa = new Crypt_RSA();

		$key = 'MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp' .
		       'wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5' .
		       '1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh' .
		       '3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2' .
		       'pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX' .
		       'GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il' .
		       'AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF' .
		       'L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k' .
		       'X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl' .
		       'U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ' .
		       '37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=';
		$this->assertTrue($rsa->loadKey($key));
	}

	public function testRawPKCS1Key()
	{
		$rsa = new Crypt_RSA();

		$key = 'MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp' .
		       'wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5' .
		       '1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh' .
		       '3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2' .
		       'pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX' .
		       'GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il' .
		       'AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF' .
		       'L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k' .
		       'X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl' .
		       'U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ' .
		       '37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=';
		$key = base64_decode($key);

		$this->assertTrue($rsa->loadKey($key));
	}

	public function testSSHPublicKey()
	{
		$rsa = new Crypt_RSA();

		$key = 'AAAAB3NzaC1yc2EAAAABIwAAAIEAo5TDX/O5ikcJdft4cPPtVLuf0sEP4Lfnn5ogVjIw5nLsElp8RIV9Y9yKqAUQwCkhAK/1P+aVnYfqj2xjq7eWKBMUdl0iSd2ti6XM5swCKDMP+Gnva9VWFgNFOgni7/OVzKTCR2yLMzaAEPszGSfqsOx8R+wkEirsj+0gwCbeREU=';

		$this->assertTrue($rsa->loadKey($key));
	}

	public function testSSHPublicKey2()
	{
		$rsa = new Crypt_RSA();

		$key = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAws84eNQp/DH47TVp/MQF7RwyqHr55SKmEnfj4rZTWNfDw4Ta6EUFIkmy7HY4Mi93zFUUPjJkTlt1z08fb+dW1weWQMalhuvLYyalAI2bU3Sw23SipBi/3d0hII3T0YpokMU53OTLbvE90ro9Zf9lg+fBdgbaN467SikwUIrWZ9nRGelj2BEOA0p2iMdUWfiiqjQpnHumBy3m0kmU6xBdLR1XcKCKDl+ErgegE3+bFx1H+pNfdZtLI0Qdn1IQeiuG+987KiuMQAhYiNo0Ne26Wp8dGivFmTt+nKnfkawUS7UTNHnuMltv5LKTysGuubjFqIAaDpCCuSl9RelST5sSrw== simqs@sbe20936';

		$this->assertTrue($rsa->loadKey($key));
	}

	public function testPKCS1PasswordCFBKey()
	{
		$rsa = new Crypt_RSA();
		$rsa->setPassword('123456789');

		$key = '-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CFB,D255C16386BF6037

oxNTij7Iu6gcwEwSHxyCpRpEPguXnZbbS01C+GeP4tx/HZpsT0jBU7tVNv9X3saM
yVySBf9bZRxB4sZU94ULPD/v8BFDhW2CYL/dsyx9opWMgcz9U0PDjsUcll1uyhXj
Qbk1od5sYX1Pq12DCuzMCtu35uFZDxSgncNb03F48zaeyumABClD1702idH+0b9e
xS0dYv531boYV/Tywf2DggjqIuYHNfIdNf/lsZ4g4OS4a5df9Yvf+eDmgP5SVo1k
MpRt2vsrrBXqFE5eScdrRtPI66vHZ4k2f8BTo1JIJm0UpY4xMbfKsxAa51X3LzxA
tVIRKaJ0r34KxVEEgiuEmkM0XJSfMYWQs9Z6rA+ds6f34+79UbrnuNY5ReAwvxAF
P1HVk3QkHS8pSYyInsCq2Dgm8Typ/aA74tkOAcjgumA5ZsQ4e5/JPFSZWvW7vi60
bf0u9yUG+LEWSEoXRSLR8ZAiOWsQVkG7FdFB62d5p9eL8TcUaIpe1Q3UgJ76qrPn
nlIDaKdZtHZ/1eeb3Jv52z9lHB7I+tJHb60uU9ZWEg+KcnxcwH8xF0ZR3REzuqGh
13YO1sVcbmmKBY6oqJISE4HBwav70fhpqA1cvdRcw3r6KNvgMHz+2SN7i0pZVH3g
3yyNaYAG5mdAgpFs6snoMDEcEa6/aQ8j7DwlCkZ3KhagCIjh5LBYc+Z1v2dZUQOs
qIRAldpmXrmQfhgGVPnrFgLmk07a0PvoJvcVHHqVzLZcpaqcHY4GpuP3IMicJQ23
//rI6Ma91c3wYRwnEpoGBwHaXXNG8a33awq/yUA+mg==
-----END RSA PRIVATE KEY-----';

		$this->assertTrue($rsa->loadKey($key));
	}

	public function testPKCS1PasswordCBCKey()
	{
		$rsa = new Crypt_RSA();
		$rsa->setPassword('123456789');

		$key = '-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CBC,5E700243F4BC1BAE

xgqLvTL3pi83L7cOhzzyohesduAaWz7BMsfFHWehTe4bhSe/WONo3rLPpVvP6oOW
6Ak3hJVvuStyLT5zfHW25sU4tOlbxoxdevoOIWfbJ8ZGhWpeWVLJl/uMQLz1yJHL
C5kUFdMaLYivbV5fprmKvp1mHE3p8OaMvbFqqVn52UINiCjFaUOWTsxMt4TUHCXQ
vaC/DGo5YLP4DhAWJFUERWmP9aZRDNb7VJLM7hY1GkoUK6+CpWwJ8stXDd+YZYQM
LZzoZVaERRjmyxRDDyR8vmNUqQUTVHyZ4KlWlPInh/eH99RmRyoq/KFaYtX9NTHW
yZ3gasSRvRcdbzcHhjEOPp/6eNA+4lM+oOKJA7AETJTNwap39jWeZ+GmR2mA/jNK
p4lnpv0ZY3/KGpI+2PyD3OF15jdggStduqj9CW0t5wxNUSOrrBi+SztTTX8BHqF7
BU5eoPv4iFa9FIuP2Vnr6V0RB37em5rq9KUtb+wWqCg9K9cZlBjHGoZJcuGfILnm
srclfQSUADUXgjurFhd+R4iYMY+z0MU1mTL9fO445DUUbSM3k1OPktCIF039Kkja
8tvsGQFASYB1qc4iXQWIzhN4XvdRoajpFJtOpF6G8bZd5ZU6MBl04DN8cmZSUf8v
AQ95BvAX3LFpJo33f1rmbQUIAQhxhcxT1nd+2gmTepguzKDAOoOzRleZ+DFilXTM
ClDB+yc7vHecj4krY3Q5YfK+Mmgvd17E6SXUByw26tZYoP9y2gtPnl7idKYaL0fG
928qmsUBQmoAx0Qpf+K5J5CGfedfQjpxx39cNxJUUUuGO2nbCIdG8nX6b5FH96cz
LYoxkMcGON/nB+0SatBtOPmmipJuVzlp9CtI1FZ/o3jRtxHPWCJBmtRA/x18obBz
4bDIs6o5HJXl84CoQpUAh/WT5bLcxuggppYvhmeTaXgebMHlpBykYL9KqdScue0/
vjnrtUkl+vZgQMxj812cykeCKfp6k65DvDkC53lBYLsVefjBdUMHKDdJSqE+fweZ
I23uWsT6wtDBukUJHYLjR23wydOKp3NgdgWR8lCinrfUj6k+FxyGflzGl7I7wCXT
aXQKi16n8/rK0A7acgWOx3iNmPKji8EolXS5T5w+xjU/rlF+CgFuFYylqmovkirU
v4EnV0IgJiLrb3ToaTXUcK3Kvo9zECQFKquaVBQNp47gjkgy1xc9Skhu76Orv8gf
1/hfQtPsoJh5ytZsNzKTnUC8DZ4krccH/ijn4dQZYeOuhpK8kfZP+OXufExvxcOj
oN/2Ls3xIjanZfE7xKa3GJcSmo2kjd+nF7WpdLzQ6a8kI5BRAomLhk9i9cz1pWzt
9TtVUnNwKVh6NCItwuNlb8jCc/hdbjBYeGhaLH1x0HaVBQEFHNaJVaGP9JCa5t4Z
sSGP4CUfN1gvCU6Cp+zgIT/iTYjMFAJejl+IcV5dvTkP7rT6uGFk+tVKpjlbpYKH
TaFMynzxn0Sa5tASXK0MWpDgIVQVGnxbnx7fcQ5UXfcjmgxEJAufAoUuekihMHl4
nDKwmlJnqLwN+Liv1rGOl7yi1KfBGX+Pdp73TEvM6etbJ3FZhsQ++A==
-----END RSA PRIVATE KEY-----';

		$this->assertTrue($rsa->loadKey($key));
	}

	public function testPuttyKey()
	{
		$rsa = new Crypt_RSA();

		$key = 'PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: rsa-key-20100224
Public-Lines: 4
AAAAB3NzaC1yc2EAAAABJQAAAIEAxmZSBp7T+US/AL6xxHMpvUY8+BdKLIIc5+BY
0xzxUtXYD/1Cyvp/V32L0dL/c/wuGal8VVIaHjP2t0bh/Kra3YfcGdRZqD0PVsNJ
wrGWmVhlH9h+41qa2rTNWJGKa/VX06SRKX0AH8ZGBQjAI/b0CdIsr4J2Yh1wmetX
dFZApsM=
Private-Lines: 8
AAAAgFXLYb2sd1cI+KZgTN9UZROT/rB4xiEVq6KKh0aJDmkChvIoVDwZS9LOgabX
yGmBzr79LtjJjsDz4E9BPyEnSeJ+oWvRA4HHtw+W2xaoOdkXbDoxX9A0zWfrUToF
6ivR83tr33C2lSxahC3jXeTNTQy5vlvNYdQhGA9kvrWKlI2tAAAAQQDpohhOujyx
9D1rR426oCiLaigryoQW/CigeEG8IhfTnuMx7JdGq6BsLIoD+7FWKeo4tccJ/IFe
I9HfL+7Qz2vTAAAAQQDZZLgyR09tQ8VLJ5CR8KrG0LEahs3Jg7HEKUCnus7MNeMJ
L92QG4jIx9Dm+1GGB/Ir7rQth6YyxSRzLoG0+bNRAAAAQGoKr/R9PXonfFnVJYAf
Ozdr7COOHXQDoskR51pNpDNJmSXZMa5gOMunSA4+JEHVjn9uyLc8bYYNg7CURlMm
Sog=
Private-MAC: c289020de3fc8aacc1796760abcd36b5ff796c5f';

		$this->assertTrue($rsa->loadKey($key));

	}

	public function testBadKey()
	{
		$rsa = new Crypt_RSA();

		$key = 'zzzzzzzzzzzzzz';

		$this->assertFalse($rsa->loadKey($key));
	}
}