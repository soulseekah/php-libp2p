<?php
namespace libp2p;

use libp2p\Noise\HandshakeState;
use phpseclib3\Crypt\EC;

class Noise {
	private int $expecting = 0;
	private $buffer;

	private HandshakeState $handshake;

	public function __construct( $initiator = false ) {
		$s = EC::createKey( 'Ed25519' );
		$this->handshake = new HandshakeState( $initiator, $s );
	}

	public function expect( int $bytes ) {
		$this->expecting = $bytes;
	}

	public function push( $buffer ) {
		list( $out, $remainder ) = self::consume( $buffer, $this->is_expecting() );
		$this->buffer .= $out;
		return $remainder;
	}

	public function is_expecting() {
		return $this->expecting - mb_strlen( $this->buffer, '8bit' );
	}

	public function tick() {
		if ( $this->is_expecting() ) {
			return;
		}

		var_dump( $this->buffer );
		var_dump( $this->handshake );
		exit;
	}

	public static function consume( $bytes, $length ) {
		return [
			mb_substr( $bytes, 0, $length, '8bit' ),
			mb_substr( $bytes, $length, null, '8bit' )
		];
	}
}

namespace libp2p\Noise;

use phpseclib3\Crypt\EC;

class CipherState {
	public $k;
	public $n;
}

class SymmetricState {
	public CipherState $cipherin;
	public CipherState $cipherout;
	public $ck;
	public $h;
}

class HandshakeState {
	public SymmetricState $symmetric;
	public EC\PrivateKey $s;
	public $e;
	public $rs;
	public $re;

	public bool $initiator;

	public function __construct( bool $initiator, EC\PrivateKey $s ) {
		$this->initiator = $initiator;
		$this->s = $s;
	}
}
