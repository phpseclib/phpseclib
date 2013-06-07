<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Maps an identifier of a known curve to a filename, loads the curve data from
 * the file and returns an Math_EcFpCurve instance.
 */
class Math_EcFpCurveFactory
{
	/**
	* Maps NIST names to curve data. The values are in order of the constructor
	* parameters of Math_EcFpCurve.
	*
	* Data from http://www.nsa.gov/ia/_files/nist-routines.pdf.
	*
	* All NIST curves have a = -3 (mod p) and cofactor = 1.
	*
	* @var array
	*/
	protected $nist_to_data = array(
		'nistp192' => array(
			'ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff',
			// 'ffffffff ffffffff ffffffff fffffffe ffffffff fffffffc',
			'-3', 
			'64210519 e59c80e7 0fa7e9ab 72243049 feb8deec c146b9b1',
			'188da80e b03090f6 7cbf20eb 43a18800 f4ff0afd 82ff1012',
			'07192b95 ffc8da78 631011ed 6b24cdd5 73f977a1 1e794811',
			'ffffffff ffffffff ffffffff 99def836 146bc9b1 b4d22831',
			'1',
		),
		'nistp224' => array(
			'ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001',
			// 'ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff fffffffe',
			'-3', 
			'b4050a85 0c04b3ab f5413256 5044b0b7 d7bfd8ba 270b3943 2355ffb4',
			'b70e0cbd 6bb4bf7f 321390b9 4a03c1d3 56c21122 343280d6 115c1d21',
			'bd376388 b5f723fb 4c22dfe6 cd4375a0 5a074764 44d58199 85007e34',
			'ffffffff ffffffff ffffffff ffff16a2 e0b8f03e 13dd2945 5c5c2a3d',
			'1',
		),
		'nistp256' => array(
			'ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff',
			// 'ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffc',
			'-3',
			'5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6 3bce3c3e 27d2604b',
			'6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296',
			'4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5',
			'ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc632551',
			'1',
		),
		'nistp384' => array(
			'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000 00000000 ffffffff',
			// 'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000 00000000 fffffffc',
			'-3', 
			'b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112 0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef',
			'aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98 59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7',
			'3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f',
			'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff c7634d81 f4372ddf 581a0db2 48b0a77a ecec196a ccc52973',
			'1',
		),
		'nistp521' => array(
			'000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff',
			// '000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffc'
			'-3',
			'00000051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b 99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd 3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00',
			'000000c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139 053fb521 f828af60 6b4d3dba a14b5e77 efe75928 fe1dc127 a2ffa8de 3348b3c1 856a429b f97e7e31 c2e5bd66',
			'00000118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449 579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901 3fad0761 353c7086 a272c240 88be9476 9fd16650',
			'000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffa 51868783 bf2f966b 7fcc0148 f709a5d0 3bb5c9b8 899c47ae bb6fb71e 91386409',
			'1',
		),
	);

	/**
	* Maps SEC curve names to NIST curve names.
	*
	* @var array
	*/
	protected $sec_to_nist = array(
		'secp192r1' => 'nistp192',
		'secp224r1' => 'nistp224',
		'secp256r1' => 'nistp256',
		'secp384r1' => 'nistp384',
		'secp521r1' => 'nistp521',
	);

	/**
	* Maps OIDs to NIST curve names.
	*/
	protected $oid_to_nist = array(
		'1.2.840.10045.3.1.1'	=> 'nistp192',
		'1.3.132.0.33'			=> 'nistp224',
		'1.2.840.10045.3.1.7'	=> 'nistp256',
		'1.3.132.0.34'			=> 'nistp384',
		'1.3.132.0.35'			=> 'nistp521',
	);

	public function fromNistName($name)
	{
		if (isset($this->nist_to_data[$name]))
		{
			return $this->makeCurve($this->nist_to_data[$name]);
		}

		return false;
	}

	public function fromSecName($name)
	{
		if (isset($this->sec_to_nist[$name]))
		{
			return $this->fromNistName($this->sec_to_nist[$name]);
		}

		return false;
	}

	public function fromOid($oid)
	{
		if (isset($this->oid_to_nist[$name]))
		{
			return $this->fromNistName($this->oid_to_nist[$name]);
		}

		return false;
	}

	/**
	* Turns an array with curve data into a curve.
	*
	* @return Math_EcFpCurve
	*/
	protected function makeCurve($data)
	{
		$reflection = new ReflectionClass('Math_EcFpCurve');

		return $reflection->newInstanceArgs(array_map(array($this, 'makeBigInteger'), $data));
	}

	/**
	* Turns a hex string into a Math_BigInteger object.
	*
	* @return Math_BigInteger
	*/
	protected function makeBigInteger($hex)
	{
		return new Math_BigInteger(str_replace(' ', '', $hex), 16);
	}
}
