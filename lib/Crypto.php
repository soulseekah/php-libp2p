<?php
namespace libp2p;

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\EC;

class Crypto {
	public static function generate_keypair( $type = 'rsa', $bits = 1024 ) {
		switch ( strtolower( $type ) ) :
			case 'rsa':
				$private = RSA::createKey( $bits );
				return [ $type, $private, $private->getPublicKey() ];
			case 'ed25519':
				$private = EC::createKey( 'Ed25519' );
				return [ $type, $private, $private->getPublicKey() ];
		endswitch;
	}
}
