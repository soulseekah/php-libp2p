<?php
namespace libp2p;

use Ramsey\Uuid\Uuid;
use Muvon\KISS\VarInt;

class Connection {
	public string $id;

	const STATE_NEW = 'new';
	const STATE_ENCRYPT = 'encrypt';
	const STATE_MPLEX = 'mplex';
	const STATE_CONNECTED = 'connected';
	const STATE_CLOSED = 'closed';

	private $state = self::STATE_NEW;

	private Node $node;
	private Peer $peer;
	private Listener $listener;
	private string $send_queue = '';

	private Noise $noise;
	private Mplex $mplex;

	public function __construct( Node $node, Peer $peer, Listener $listener ) {
		$this->id = Uuid::uuid4();
		$this->node = $node;
		$this->peer = $peer;
		$this->listener = $listener;
	}

	public function close() {
		$this->state = self::STATE_CLOSED;
	}

	public function recv( $bytes ) {
		static $buffer = '';

		if ( empty( $buffer .= $bytes ) ) {
			return;
		}

		switch ( $this->state ) :
			case self::STATE_NEW:
				list( $length, $seek ) = VarInt::readUint( bin2hex( $buffer ) );
				list( $out, $buffer )  = self::consume( $buffer, $seek / 2 );
				list( $out, $buffer )  = self::consume( $buffer, $length );

				if ( trim( $out ) === '/multistream/1.0.0' ) {
					$this->send( hex2bin( VarInt::packUint( Crypto::len( $out ) ) ) . $out );
					break;
				}

				if ( trim( $out ) === '/noise' ) {
					$this->noise = new Noise( $this->listener->log, $this->peer->keypair, false );
					$this->state = self::STATE_ENCRYPT;
					$this->send( hex2bin( VarInt::packUint( Crypto::len( $out ) ) ) . $out );
					break;
				}

				$out = "na\n";
				$this->send( hex2bin( VarInt::packUint( Crypto::len( $out ) ) ) . $out );
				break;

			case self::STATE_ENCRYPT:
				$buffer = $this->noise->push( $buffer );
				$this->send( $this->noise->tick() );
				if ( $this->noise->is_connected() ) {
					$this->state = self::STATE_MPLEX;
				}
				break;
			case self::STATE_MPLEX:
				$buffer = $this->noise->push( $buffer );
				if ( $this->noise->is_expecting() ) {
					break;
				}

				if ( $data = $this->noise->decrypt() ) while ( $data ) {
					list( $length, $seek ) = VarInt::readUint( bin2hex( $data ) );
					list( $out, $data )    = self::consume( $data, $seek / 2 );
					list( $out, $data )    = self::consume( $data, $length );

					if ( trim( $out ) === '/multistream/1.0.0' ) {
						$out = hex2bin( VarInt::packUint( Crypto::len( $out ) ) ) . $out;
						$out = $this->noise->encrypt( $out );
						$this->send( pack( 'n', Crypto::len( $out ) ) . $out );
						continue;
					}

					if ( trim( $out ) === '/mplex/6.7.0' ) {
						$out = hex2bin( VarInt::packUint( Crypto::len( $out ) ) ) . $out;
						$out = $this->noise->encrypt( $out );
						$this->send( pack( 'n', Crypto::len( $out ) ) . $out );
						$this->state = self::STATE_CONNECTED;
						continue;
					}

					$out = "na\n";
					$out = hex2bin( VarInt::packUint( Crypto::len( $out ) ) ) . $out;
					$out = $this->noise->encrypt( $out );
					$this->send( pack( 'n', Crypto::len( $out ) ) . $out );
				}
				break;
			case self::STATE_CONNECTED:
				$buffer = $this->noise->push( $buffer );
				if ( $this->noise->is_expecting() ) {
					break;
				}

				if ( $data = $this->noise->decrypt() ) while ( $data ) {
					var_dump( $data );
					exit;
				}

				break;
		endswitch;
	}

	public static function consume( $bytes, $length ) {
		return [
			mb_substr( $bytes, 0, $length, '8bit' ),
			mb_substr( $bytes, $length, null, '8bit' )
		];
	}

	public function send( $bytes ) {
		$this->send_queue .= $bytes;
	}

	public function pop_send_queue() {
		$send = $this->send_queue;
		$this->send_queue = '';
		return $send;
	}
}
