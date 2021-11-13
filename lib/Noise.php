<?php
namespace libp2p;

use libp2p\Noise\HandshakeState;
use phpseclib3\Crypt\RSA;

class Noise {
	private int $expecting = 0;
	private $buffer;
	private array $keypair;

	private HandshakeState $handshake;

	public \Monolog\Logger $log;

	public function __construct( \Monolog\Logger $log, array $keypair, bool $initiator ) {
		$this->log = $log->withName( static::class );
		$this->keypair = $keypair;
		// $this->handshake = new HandshakeState( $initiator, sodium_crypto_box_keypair() );
		$this->handshake = new HandshakeState( $initiator, hex2bin( 'a3a203e9630758e589476fc55c339c79d6d270573ca95f177703da03f6dd2dbedfa385060bce7e429ccc2b30d1edc8b8db00d1a803ac67040f0823a4c725596c' ) );
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

		if ( $this->handshake->stage === 0 ) {
			// Stage 0
			if ( Crypto::len( $this->buffer ) !== 32 ) {
				$this->log->error( 'Unexpected handshake e', [ 'bytes' => trim( chunk_split( bin2hex( $this->buffer ), 2, ' ' ) ) ] );
				return;
			}

			$this->log->debug( 'Handshake: stage 0 received Message A', [ 'e' => bin2hex( $this->buffer ) ] );
			$this->handshake->re = $this->buffer;
			$this->handshake->symmetric->MixHash( $this->handshake->re );
			$this->handshake->symmetric->MixHash( '' );

			// Stage 1
			$payload = Crypto::to_object( $this->keypair['private'] )
				->withPadding( RSA::SIGNATURE_PKCS1 )
				->sign( 'noise-libp2p-static-key:' . sodium_crypto_box_publickey( $this->handshake->s ) );

			$pb_payload = new Protobuf\Noise\HandshakePayload();
			$pb_payload->setIdentityKey( Crypto::marshal( $this->keypair['public'] ) );
			$pb_payload->setIdentitySig( $payload );
			$pb_payload->setData( null );

			return $this->send( $pb_payload->serializeToString() );
		}
		
		var_dump( $this->handshake->stage );
		var_dump( bin2hex( $this->buffer ) );
		exit;
	}

	public function send( $bytes ) {
		if ( $this->handshake->stage === 0 ) {
			// $this->handshake->e = sodium_crypto_box_keypair();
			$this->handshake->e = hex2bin( 'f3472b81ce399447f68d1ad42e1a8e2a7e2c74d205ed577d72f4fcc007a3d591e85df89fb80d2ef1e306d941f7e481ec2405c893a458709457a01df767497d34' );;
			$e = sodium_crypto_box_publickey( $this->handshake->e );

			$this->handshake->symmetric->MixHash( $e );
			$this->handshake->symmetric->MixKey( sodium_crypto_scalarmult( sodium_crypto_box_secretkey( $this->handshake->e ), $this->handshake->re ) );

			$s = $this->handshake->symmetric->EncryptAndHash( sodium_crypto_box_publickey( $this->handshake->s ) );
			$this->handshake->symmetric->MixKey( sodium_crypto_scalarmult( sodium_crypto_box_secretkey( $this->handshake->s ), $this->handshake->re ) );

			$payload = $this->handshake->symmetric->EncryptAndHash( $bytes );

			$this->log->debug( 'Handshake: stage 1 sent Message B', [
				'e' => bin2hex( $e ),
				's' => bin2hex( sodium_crypto_box_publickey( $this->handshake->s ) ),
				'payload' => bin2hex( $bytes ),
			] );

			$out = implode( '', [ $e, $s, $payload ] );

			$this->handshake->stage++;

			return pack( 'n', Crypto::len( $out ) ) . $out;
		}
	}

	public static function consume( $bytes, $length ) {
		return [
			mb_substr( $bytes, 0, $length, '8bit' ),
			mb_substr( $bytes, $length, null, '8bit' )
		];
	}
}

namespace libp2p\Noise;

class CipherState {
	public $k;
	public $n;
}

class SymmetricState {
	public CipherState $cipher;
	public $ck;
	public $h;

	public function __construct() {
		$this->h = 'Noise_XX_25519_ChaChaPoly_SHA256';
		$this->ck = $this->h;
		$this->MixHash( '' );
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
	}

	public function EncryptAndHash( $plaintext ) {
		$ciphertext = sodium_crypto_aead_chacha20poly1305_ietf_encrypt( $plaintext, $this->h, pack( 'xxxxP', $this->cipher->n ), $this->cipher->k );
		$this->MixHash( $ciphertext );
		$this->cipher->n++;
		return $ciphertext;
	}
}

class HandshakeState {
	public SymmetricState $symmetric;
	public string $s;
	public string $e;
	public string $rs;
	public string $re;
	public int $stage = 0;

	public bool $initiator;

	public function __construct( bool $initiator, string $s ) {
		$this->initiator = $initiator;
		$this->s = $s;

		$this->symmetric = new SymmetricState();
	}

	public function dump() {
		$h = 'bin2hex';
		return [
			's' => $h( $this->s ),
			'e' => $h( $this->e ),
			're' => $h( $this->re ),

			'ss' => [
				'cs' => [
					'k' => $h( $this->symmetric->cipher->k ),
					'n' => $this->symmetric->cipher->n,
				],
				'ck' => $h( $this->symmetric->ck ),
				'h' => $h( $this->symmetric->h ),
			],
		];
	}
}
