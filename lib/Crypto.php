<?php
namespace libp2p;

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\PublicKeyLoader;
use StephenHill\Base58;

class Crypto {
	public static function generate_keypair( $type = 'rsa', $bits = 1024 ) {
		switch ( strtolower( $type ) ) :
			case 'rsa':
				$private = RSA::createKey( $bits );

				$public = $private->getPublicKey();

				$public = PublicKeyLoader::load(file_get_contents('/tmp/pub.pem'), $password = false);

				return [
					'type'    => $type,
					'private' => $private->toString( 'pkcs1' ),
					'public'  => $public->toString( 'pkcs1' ),
				];
		endswitch;

		throw new \InvalidArgumentException( "Invalid type: $type" );
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
