<?php
namespace libp2p;

use libp2p\Noise\HandshakeState;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\DH;

class Noise {
	private int $expecting = 0;
	private $buffer;
	private array $keypair;

	private HandshakeState $handshake;

	public \Monolog\Logger $log;

	public function __construct( \Monolog\Logger $log, array $keypair, bool $initiator ) {
		$this->log = $log->withName( static::class );
		$this->keypair = $keypair;
		$this->handshake = new HandshakeState( $initiator, EC::createKey( 'Curve25519' ) );
	}

	public function expect( int $bytes ) {
		$this->expecting = $bytes;
	}

	public function push( $buffer ) {
		if ( ! $this->is_expecting() ) {
			list( $length, $buffer ) = self::consume( $buffer, 2 );
			$this->expect( hexdec( bin2hex( $length ) ) );
		}

		list( $buffer, $remainder ) = self::consume( $buffer, $this->is_expecting() );
		$this->buffer .= $buffer;
		return $remainder;
	}

	public function is_expecting() {
		return $this->expecting - Crypto::len( $this->buffer );
	}

	public function tick() {
		if ( $this->is_expecting() ) {
			return;
		}

		if ( Crypto::len( $this->buffer ) !== 32 ) {
			$this->log->error( 'Unexpected handshake e', [ 'bytes' => trim( chunk_split( bin2hex( $this->buffer ), 2, ' ' ) ) ] );
			return;
		}

		$this->log->debug( 'Handshake e', [ 'bytes' => trim( chunk_split( bin2hex( $this->buffer ), 2, ' ' ) ) ] );
		$this->handshake->re = $this->buffer;
		$this->handshake->symmetric->MixHash( $this->handshake->re );

		$payload = Crypto::to_object( $this->keypair['private'] )
			->sign( 'noise-libp2p-static-key:' . $this->handshake->s->getPublicKey()->getEncodedCoordinates() );

		$pb_payload = new Protobuf\Noise\HandshakePayload();
		$pb_payload->setIdentityKey( Crypto::marshal( $this->keypair['public'] ) );
		$pb_payload->setIdentitySig( $payload = Crypto::to_object( $this->keypair['private'] )
			->sign( 'noise-libp2p-static-key:' . $this->handshake->s->getPublicKey()->getEncodedCoordinates() ) );

		return $this->send( $pb_payload->serializeToString() );
	}

	public function send( $bytes ) {
		$this->handshake->e = EC::createKey( 'Curve25519' );
		$out = $this->handshake->e->getPublicKey()->getEncodedCoordinates();

		$this->handshake->symmetric->MixHash( $this->handshake->e );
		$this->handshake->symmetric->MixKey( DH::computeSecret( $this->handshake->e, $this->handshake->re ) );
		exit;

		return pack( 'n', Crypto::len( $out ) ) . $out;
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
use phpseclib3\Crypt\ChaCha20;

class CipherState {
	public $k;
	public $n;

	public ChaCha20 $c;
}

class SymmetricState {
	public CipherState $cipher;
	public $ck;
	public $h;

	public function __construct() {
		$this->h = hash( 'sha256', 'Noise_XX_25519_ChaChaPoly_SHA256', true );
		$this->ck = $this->h;

		$this->cipher = new CipherState();
	}

	public function MixHash( $data ) {
		$this->h = hash( 'sha256', $this->h . $data, true );
	}

	public function MixKey( $key ) {
		$this->cipher->n = 0;

		$iv = hash_hmac( 'sha256', $key, $this->ck, true );
		$this->ck = hash_hmac( 'sha256', "\x01", $iv, true );
		$this->cipher->k = hash_hmac( 'sha256', $this->ck . "\x02", $iv, true );
		$this->cipher->c = new ChaCha20();
		$this->cipher->c->setKey( $this->cipher->k );
	}
}

class HandshakeState {
	public SymmetricState $symmetric;
	public EC\PrivateKey $s;
	public EC\PrivateKey $e;
	public $rs;
	public $re;

	public bool $initiator;

	public function __construct( bool $initiator, EC\PrivateKey $s ) {
		$this->initiator = $initiator;
		$this->s = $s;

		$this->symmetric = new SymmetricState();
	}
}
