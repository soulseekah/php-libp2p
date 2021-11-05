<?php
namespace libp2p\Listeners;

use libp2p\{Node, Address, Listener, Connection};

class TCP extends Listener {
	private Node $node;
	private Address $address;

	private $socket;
	private array $clients;

	const LEN_BUFFER = 2048;

	public function __construct( $transport, Node $node, Address $address ) {
		$this->address = $address;
		$this->node    = $node;

		call_user_func_array( [ parent::class, __FUNCTION__ ], func_get_args() );
	}

	public function listen() {
		$this->socket = socket_create( AF_INET, SOCK_STREAM, getprotobyname( 'tcp' ) );

		socket_set_nonblock( $this->socket );
		socket_set_option( $this->socket, SOL_SOCKET, SO_REUSEADDR, 1 );

		list( $ip, $port ) = $this->address->get_protocols();

		if ( ! socket_bind( $this->socket, end( $ip ), end( $port ) ) ) {
			throw new \InvalidArgumentException( 'Socket error ' . socket_strerror( socket_last_error( $this->socket ) ) );
		}

		$this->log->info( 'listen()', [
			'ip' => end( $ip ), 'port' => end( $port ),
		] );

		socket_listen( $this->socket );

		$this->clients = [];
	}

	public function poll() {
		$read = $write = $except = array_merge( [ $this->socket ], $this->clients );

		if ( ! socket_select( $read, $write, $except, 0 ) ) {
			return;
		}

		foreach ( $except as $socket ) {
			var_dump( $except );
			exit;
		}

		foreach ( $read as $socket ) {
			if ( $socket === $this->socket ) {
				$client = socket_accept( $this->socket );

				socket_getpeername( $client, $address, $port );
				$this->log->debug( 'accept()', compact( 'address', 'port' ) );

				$connection = new Connection( $this );
				$this->clients[ $connection->id ] = $client;

				$this->node->accept( $connection );
			} else {
				$connection_id = array_search( $socket, $this->clients );
				$this->recv( $connection_id, $length = socket_read( $socket, self::LEN_BUFFER ) );

				if ( ! $length ) {
					unset( $this->clients[ $connection_id ] );
					$this->node->connections[ $connection_id ]->close();

					$this->log->debug( 'close()', [ 'connection_id' => $connection_id ] );
				}
			}
		}

		foreach ( $write as $socket ) {
			if ( $connection_id = array_search( $socket, $this->clients ) ) {
				if ( $bytes = $this->fetch( $connection_id ) ) {
					$len = socket_write( $socket, $bytes );
					if ( $len != mb_strlen( $bytes, '8bit' ) ) {
						$this->pushback( $connection_id, mb_substr( $bytes, $len - 1, '8bit' ) );
					}
					$this->log->debug( "send() $len bytes", [ 
						'connection_id' => $connection_id,
						'bytes' => trim( chunk_split( bin2hex( $bytes ), 2, ' ' ) ),
					] );
				}
			}
		}

		foreach ( $this->node->connections as $connection ) {
			$connection->recv( '' );
		}
	}

	private function recv( $connection_id, $bytes ) {
		if ( ! $bytes ) {
			return;
		}

		$this->log->debug( 'recv()', [
			'connection_id' => $connection_id,
			'bytes' => trim( chunk_split( bin2hex( $bytes ), 2, ' ' ) ),
		] );
		$this->node->connections[ $connection_id ]->recv( $bytes );
	}

	private function fetch( $connection_id ) {
		return $this->node->connections[ $connection_id ]->pop_send_queue();
	}

	private function pushback( $connection_id, $bytes ) {
		$this->node->connections[ $connection_id ]->pushback( $bytes );
	}
}
