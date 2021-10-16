<?php
namespace libp2p;

use libp2p\Protobuf;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Crypt\PublicKeyLoader;

class Peer {
	public function __construct() {
		$this->keypair = Crypto::generate_keypair();

		$raw = PublicKeyLoader::load( $this->keypair['public'] )->toString( 'raw' );

		$der = ASN1::encodeDER( [
			'publicKey' => chr( 0x00 /** unused bits */ ) . ASN1::encodeDER( [
				'modulus' => $raw['n'],
				'publicExponent' => $raw['e'],
			], [
				'type' => ASN1::TYPE_SEQUENCE,
				'children' => [
					'modulus' => [ 'type' => ASN1::TYPE_INTEGER ],
					'publicExponent' => [ 'type' => ASN1::TYPE_INTEGER ],
				],
			] ),
			'publicKeyAlgorithm' => [
				'algorithm' => ASN1::getOID( 'rsaEncryption' ),
				'parameters' => null,
			],
		], [
			'type' => ASN1::TYPE_SEQUENCE,
			'children' => [
				'publicKeyAlgorithm' => [
					'type' => ASN1::TYPE_SEQUENCE,
					'children' => [
						'algorithm' => [ 'type' => ASN1::TYPE_OBJECT_IDENTIFIER ],
						'parameters' => [ 'type' => ASN1::TYPE_NULL ],
					]
				],
				'publicKey' => [ 'type' => ASN1::TYPE_BIT_STRING ],
			],
		] );

		$pb_public = new Protobuf\Crypto\PublicKey();
		$pb_public->setType( Protobuf\Crypto\KeyType::RSA );
		$pb_public->setData( $der );

		$pb_public = $pb_public->serializeToString();

		$this->id = Crypto::multihash(
			$pb_public,
			Crypto::len( $pb_public ) <= 42 ? 'identity': 'sha2-256',
			'base58btc',
		);
	}
}
