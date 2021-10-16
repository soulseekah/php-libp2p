<?php
namespace libp2p;

use Aimeos\Map;
use Evenement\EventEmitter;

class Node extends EventEmitter {
	private array $listen;

	public function __construct( $peer, $opts ) {
		$opts = Map::from( $opts );

		foreach ( $opts->get( 'addresses/listen' ) as $address ) {
			if ( $address = new Address( $address ) ) {
				$this->listen[] = $address;
			}
		}

		var_dump( $this->listen );
	}

	public function start() {
	}

	public function handle() {
	}
}
