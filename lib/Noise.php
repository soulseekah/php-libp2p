<?php
namespace libp2p;

use libp2p\Noise\HandshakeState;
use phpseclib3\Crypt\RSA;

class Noise {
	private int $expecting = 0;
	private $buffer;
	private array $keypair;

	private HandshakeState $handshake;
	private array $ciphers;

	private Peer $peer;

	public \Monolog\Logger $log;

	public function __construct( \Monolog\Logger $log, array $keypair, bool $initiator ) {
		$this->log = $log->withName( static::class );
		$this->keypair = $keypair;
		// $this->handshake = new HandshakeState( $initiator, sodium_crypto_box_keypair() );
		$this->handshake = new HandshakeState( $initiator, hex2bin( 'a3a203e9630758e589476fc55c339c79d6d270573ca95f177703da03f6dd2dbedfa385060bce7e429ccc2b30d1edc8b8db00d1a803ac67040f0823a4c725596c' ) );
	}

	public function is_connected() {
		return $this->handshake && ( $this->handshake->stage > 2 );
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

		$this->expecting = 0;

		if ( $this->handshake->stage === 0 ) {
			// Stage 0
			if ( Crypto::len( $this->buffer ) !== 32 ) {
				$this->log->error( 'Unexpected handshake: stage 0 received Message A', [ 'bytes' => trim( chunk_split( bin2hex( $this->buffer ), 2, ' ' ) ) ] );
				return;
			}

			$this->log->debug( 'Handshake: stage 0 received Message A', [ 'e' => bin2hex( $this->buffer ) ] );

			list( $this->handshake->re, $this->buffer ) = self::consume( $this->buffer, 32 );
			$this->handshake->symmetric->MixHash( $this->handshake->re );
			$this->handshake->symmetric->MixHash( '' );

			$this->handshake->stage++;

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

		if ( $this->handshake->stage === 2 ) {
			// Stage 2
			if ( Crypto::len( $this->buffer ) < 48 ) {
				$this->log->error( 'Unexpected handshake: stage 2 received Message C', [ 'bytes' => trim( chunk_split( bin2hex( $this->buffer ), 2, ' ' ) ) ] );
				return;
			}

			list( $s, $this->buffer ) = self::consume( $this->buffer, 48 );
			list( $payload, $this->buffer ) = self::consume( $this->buffer, Crypto::len( $this->buffer ) );

			$this->handshake->rs = $this->handshake->symmetric->DecryptAndHash( $s );
			$this->handshake->symmetric->MixKey( sodium_crypto_scalarmult( sodium_crypto_box_secretkey( $this->handshake->e ), $this->handshake->rs ) );
			$payload = $this->handshake->symmetric->DecryptAndHash( $payload );

			$this->ciphers = $this->handshake->symmetric->Split();

			$this->log->debug( 'Handshake: stage 2 received Message C', [
				's' => bin2hex( $this->handshake->rs ),
				'payload' => bin2hex( $payload ),
			] );

			$pb_payload = new Protobuf\Noise\HandshakePayload();
			$pb_payload->mergeFromString( $payload );

			$this->peer = new Peer( null, Crypto::unmarshal( $pb_payload->getIdentityKey() ) );

			$verifies = Crypto::to_object( $this->peer->keypair['public'] )
				->withPadding( RSA::SIGNATURE_PKCS1 )
				->verify( 'noise-libp2p-static-key:' . $this->handshake->rs, $pb_payload->getIdentitySig() );

			if ( ! $verifies ) {
				$this->log->error( 'Handshake: stage 2 does not verify. Aborting.' );
				return;
			}

			$this->handshake->stage++;
			return;
		}
	}

	public function decrypt() {
		if ( $this->is_expecting() ) {
			return;
		}

		$this->expecting = 0;
		$ciphertext = $this->buffer;
		$this->buffer = '';

		$cipher = $this->handshake->initiator ? $this->ciphers[1] : $this->ciphers[0];
		return $cipher->DecryptWithAd( '', $ciphertext );
	}

	public function encrypt( $plaintext ) {
		$cipher = $this->handshake->initiator ? $this->ciphers[0] : $this->ciphers[1];
		return $cipher->EncryptWithAd( '', $plaintext );
	}

	public function send( $bytes ) {
		if ( $this->handshake->stage === 1 ) {
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

	public function InitializeKey( $key ) {
		$this->k = $key;
		$this->n = 0;
	}

	public function EncryptWithAd( $ad, $plaintext ) {
		return sodium_crypto_aead_chacha20poly1305_ietf_encrypt( $plaintext, $ad, pack( 'xxxxP', $this->n++ ), $this->k );
	}

	public function DecryptWithAd( $ad, $ciphertext ) {
		return sodium_crypto_aead_chacha20poly1305_ietf_decrypt( $ciphertext, $ad, pack( 'xxxxP', $this->n++ ), $this->k );
	}

	public function dump() {
		return [
			'k' => bin2hex( $this->k ),
			'n' => $this->n,
		];
	}
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
		$iv = hash_hmac( 'sha256', $key, $this->ck, true );
		$this->ck = hash_hmac( 'sha256', "\x01", $iv, true );
		$this->cipher->InitializeKey( hash_hmac( 'sha256', $this->ck . "\x02", $iv, true ) );
	}

	public function EncryptAndHash( $plaintext ) {
		$ciphertext = $this->cipher->EncryptWithAd( $this->h, $plaintext );
		$this->MixHash( $ciphertext );
		return $ciphertext;
	}

	public function DecryptAndHash( $ciphertext ) {
		$plaintext = $this->cipher->DecryptWithAd( $this->h, $ciphertext );
		$this->MixHash( $ciphertext );
		return $plaintext;
	}

	public function Split() {
		$okm = hash_hmac( 'sha256', '', $this->ck, true );
		return array_map( function( $k ) {
			$c = new CipherState();
			$c->InitializeKey( $k );
			return $c;
		}, [
			$prev = hash_hmac( 'sha256', "\x1", $okm, true ),
			hash_hmac( 'sha256', "$prev\x2", $okm, true )
		] );
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
			'rs' => $h( $this->rs ),
			're' => $h( $this->re ),

			'ss' => [
				'h' => $h( $this->symmetric->h ),
				'ck' => $h( $this->symmetric->ck ),
				'cs' => $this->symmetric->cipher->dump(),
			],
		];
	}
}
