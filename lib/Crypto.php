<?php
namespace libp2p;

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\EC;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Crypt\PublicKeyLoader;
use StephenHill\Base58;

class Crypto {
	public static function generate_keypair( $type = 'rsa', $bits = 1024 ) {
		switch ( strtolower( $type ) ) :
			case 'rsa':
				$private = RSA::createKey( $bits );
				$public = $private->getPublicKey();

				return [
					'type'    => $type,
					'private' => $private->toString( 'pkcs1' ),
					'public'  => $public->toString( 'pkcs1' ),
				];
		endswitch;

		throw new \InvalidArgumentException( "Invalid type: $type" );
	}

	public static function to_object( $key ) {
		return PublicKeyLoader::load( $key );
	}

	public static function marshal( $key ) {
		$raw = self::to_object( $key )->toString( 'raw' );

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

		return $pb_public->serializeToString();
	}

	public static function unmarshal( $public ) {
		$pb_public = new Protobuf\Crypto\PublicKey();
		$pb_public->mergeFromString( $public );

		if ( $pb_public->getType() === Protobuf\Crypto\KeyType::RSA ) {
			$der = ASN1::asn1map( ASN1::decodeBER( $pb_public->getData() )[0], [
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

			$der = ASN1::asn1map( ASN1::decodeBER( mb_substr( $der['publicKey'], 1, null, '8bit' ) )[0], [
				'type' => ASN1::TYPE_SEQUENCE,
				'children' => [
					'modulus' => [ 'type' => ASN1::TYPE_INTEGER ],
					'publicExponent' => [ 'type' => ASN1::TYPE_INTEGER ],
				],
			] );

			return PublicKeyLoader::load( [
				'e' => $der['publicExponent'],
				'n' => $der['modulus'],
			] )->toString( 'pkcs1' );
		}
	}

	public static function multihash( $data, $name, $encode = null ) {
		switch ( strtolower( $name ) ) :
			case 'sha2-256':
				$digest = hash( 'sha256', $data, 'true' );
				$digest = chr( 0x12 ) . chr( self::len( $digest ) ) . $digest;
				break;
			default:
				throw new \InvalidArgumentException( "Invalid name: $name" );
		endswitch;

		switch ( strtolower( $encode ) ) :
			case null:
				return $digest;
			case 'base58btc':
				return ( new Base58() )->encode( $digest );
			default:
				throw new \InvalidArgumentException( "Invalid encode: $encode" );
		endswitch;
	}

	public static function len( $data ) {
		return mb_strlen( $data, '8bit' );
	}
}
