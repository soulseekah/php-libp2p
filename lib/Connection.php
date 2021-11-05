<?php
namespace libp2p;

use Ramsey\Uuid\Uuid;
use Muvon\KISS\VarInt;

class Connection {
	public string $id;

	const STATE_NEW = 'new';
	const STATE_HANDSHAKE= 'handshake';
	const STATE_CLOSED = 'closed';

	private $state = self::STATE_NEW;

	private Listener $listener;
	private string $send_queue = '';

	private Noise $noise;

	public function __construct( Listener $listener ) {
		$this->id = Uuid::uuid4();
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
					$this->queue_send( hex2bin( VarInt::packUint( mb_strlen( $out, '8bit' ) ) ) . $out );
					break;
				}

				if ( trim( $out ) === '/noise' ) {
					$this->noise = new Noise();
					$this->state = self::STATE_HANDSHAKE;
					$this->queue_send( hex2bin( VarInt::packUint( mb_strlen( $out, '8bit' ) ) ) . $out );
					break;
				}

				$out = "na\n";
				$this->queue_send( hex2bin( VarInt::packUint( mb_strlen( $out, '8bit' ) ) ) . $out );
				break;

			case self::STATE_HANDSHAKE:
				if ( ! $this->noise->is_expecting() ) {
					list( $length, $buffer ) = self::consume( $buffer, 2 );
					$this->noise->expect( hexdec( bin2hex( $length ) ) );
				}

				$buffer = $this->noise->push( $buffer );

				$this->noise->tick();
				break;
		endswitch;
	}

	public static function consume( $bytes, $length ) {
		return [
			mb_substr( $bytes, 0, $length, '8bit' ),
			mb_substr( $bytes, $length, null, '8bit' )
		];
	}

	public function queue_send( $bytes ) {
		$this->send_queue .= $bytes;
	}

	public function pop_send_queue() {
		$send = $this->send_queue;
		$this->send_queue = '';
		return $send;
	}
}
