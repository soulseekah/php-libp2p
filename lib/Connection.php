<?php
namespace libp2p;

use Ramsey\Uuid\Uuid;
use Muvon\KISS\VarInt;

class Connection {
	public string $id;

	const STATE_NEW = 'new';
	const STATE_CLOSED = 'closed';

	private $state = self::STATE_NEW;

	private Listener $listener;
	private string $send_queue = '';

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
				list( $out, $buffer )   = self::consume( $buffer, $seek );
				list( $out, $buffer )   = self::consume( $buffer, $length );

				if ( trim( $out ) === '/multistream/1.0.0' ) {
					$this->queue_send( hex2bin( VarInt::packUint( mb_strlen( $out, '8bit' ) ) ) . $out );
					break;
				}

				$out = "na\n";
				$this->queue_send( hex2bin( VarInt::packUint( mb_strlen( $out, '8bit' ) ) ) . $out );
				break;
		endswitch;
	}

	public static function consume( $bytes, $length ) {
		return [
			mb_substr( $bytes, 0, $length, '8bit' ),
			mb_substr( $bytes, $length - 1, null, '8bit' )
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
