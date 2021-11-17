<?php
namespace libp2p;

use Muvon\KISS\VarInt;

class Mplex {
	private array $streams;

	public Node $node;
	public Peer $peer;

	public \Monolog\Logger $log;

	public function __construct( Node $node, Peer $peer ) {
		$this->log = $node->log->withName( static::class );
		$this->node = $node;
		$this->peer = $peer;
	}

	public function recv( $data ) {
		if ( empty( $data ) ) {
			return;
		}

		list( $header, $seek ) = VarInt::readUint( bin2hex( $data ) );
		$flag = $header & 0x07;
		$id = $header >> 3;

		list( $_, $data ) = self::consume( $data, $seek / 2 );
		list( $length, $seek ) = VarInt::readUint( bin2hex( $data ) );
		list( $_, $data ) = self::consume( $data, $seek / 2 );
		list( $data, $remaining ) = self::consume( $data, $length );

		switch ( $flag ) {
			case Mplex\Flag::NewStream:
				if ( isset( $this->streams[ $id ] ) ) {
					$this->log->error( "Stream $id already exists" );
					break;
				}

				$this->streams[ $id ] = new Mplex\Stream( $id, $name = $data, $this, false );

				break;
			case Mplex\Flag::MessageInitiator:
				if ( empty( $this->streams[ $id ] ) ) {
					$this->log->error( "Stream $id does not exist" );
					break;
				}

				$this->streams[ $id ]->recv( $data );
				break;
			default:
				$this->log->critical( "Unknown message flag $flag" );
		}

		return $remaining;
	}

	public function get_send() {
		$send = [];
		foreach ( $this->streams as $stream ) {
			if ( $data = $stream->get_send() ) {
				$header = ( $stream->id << 3 ) | Mplex\Flag::MessageReceiver;
				$send[] = hex2bin( VarInt::packUint( $header ) ) . hex2bin( VarInt::packUint( Crypto::len( $data ) ) ) . $data;
			}
		}
		return $send;
	}

	public static function consume( string $bytes, int $length ) {
		return [
			mb_substr( $bytes, 0, $length, '8bit' ),
			mb_substr( $bytes, $length, null, '8bit' )
		];
	}
}

namespace libp2p\Mplex;

use libp2p\{Node, Peer, Mplex, Crypto};
use Muvon\KISS\VarInt;

class Flag {
	const NewStream = 0;
	const MessageReceiver = 1;
	const MessageInitiator = 2;
	const CloseReceiver = 3;
	const CloseInitiator = 4;
	const ResetReceiver = 5;
	const ResetInitiator = 6;
}

class Status {
	const NEW = 0;
	const CONNECTED = 1;
}

class Stream {
	public int $id;
	private string $name;
	private Mplex $mplex;

	private int $status;
	private string $buffer = '';
	private string $send = '';
	private $handler;

	public bool $is_initiator;

	public function __construct( int $id, string $name, Mplex $mplex, bool $is_initiator) {
		$this->id = $id;
		$this->mplex = $mplex;
		$this->status = Status::NEW;
		$this->is_initiator = $is_initiator;
	}

	public function recv( $data ) {
		$this->buffer .= $data;

		while ( $this->buffer ) {
			switch ( $this->status ) {
				case Status::NEW:
					list( $length, $seek ) = VarInt::readUint( bin2hex( $this->buffer ) );
					list( $_, $this->buffer ) = $this->mplex::consume( $this->buffer, $seek / 2 );
					list( $data, $this->buffer ) = $this->mplex::consume( $this->buffer, $length );

					if ( trim( $data ) == "/multistream/1.0.0" ) {
						$this->send( hex2bin( VarInt::packUint( Crypto::len( $data ) ) ) . $data );
						break;
					}

					$handlers = $this->mplex->node->handlers;

					if ( isset( $handlers[ $protocol = trim( $data ) ] ) ) {
						$this->handler = $handlers[ $protocol ];
						$this->status = Status::CONNECTED;

						$this->send( hex2bin( VarInt::packUint( Crypto::len( $data ) ) ) . $data );
						break;
					}

					$this->mplex->log->error( "Unknown protocol $protocol", [
						'protocols' => array_keys( $handlers ),
					] );

					$data = "na\n";
					$this->send( hex2bin( VarInt::packUint( Crypto::len( $data ) ) ) . $data );
					break;
				case Status::CONNECTED:
					if ( is_callable( $this->handler ) ) {
						$data = $this->buffer;
						$this->buffer = '';
						( $this->handler )( $data, $this, $this->mplex->peer, $this->mplex->node );
					}
					break;
			}
		}
	}

	public function send( $data ) {
		$this->send .= $data;
	}

	public function get_send() {
		$data = $this->send;
		$this->send = '';
		return $data;
	}
}
