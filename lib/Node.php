<?php
namespace libp2p;

use Monolog\Logger;

use Aimeos\Map;
use Evenement\EventEmitter;

class Node extends EventEmitter {

	private Peer $peer;
	private Map $addresses;

	private array $_listeners;
	public array $connections;

	public Logger $log;

	public function __construct( Peer $peer, $opts ) {
		$this->peer = $peer;

		$opts = Map::from( $opts );

		$this->addresses = Map::from( $opts->get( 'addresses', [] ) )->walk( function( &$address ) {
			$address = new Address( $address );
		} );

		$this->log = new Logger( 'libp2p' );
	}

	public function start() {
		$this->log->info( "Starting node", [ 'peer_id' => $this->peer->id ] );

		foreach ( $this->addresses->get( 'listen', [] ) as $address ) {
			$this->_listeners[] = Transport::create_listener( $this, $address );
		}

		foreach ( $this->_listeners as $listener ) {
			$listener->listen();
		}

		while ( $this->_listeners ) {
			foreach ( $this->_listeners as $listener ) {
				$listener->poll();
			}
		}

		$this->emit( 'started' );
	}

	public function stop() {
		foreach ( $this->_listeners as $listener ) {
			$listener->close();
		}

		$this->_listeners = [];

		$this->emit( 'stopped' );
	}

	public function handle() {
	}

	public function accept( Connection $connection ) {
		$this->log->info( 'accept()', [ 'connection_id' => $connection->id ] );
		$this->connections[ $connection->id ] = $connection;

		$this->emit( 'accept' );
	}

	public function dial( Address $address ) {
	}
}
