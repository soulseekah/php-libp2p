<?php
namespace libp2p;

use Aimeos\Map;

class Node {
	public function __construct( $args ) {
		var_dump( Map::from( $args ) );
	}
}
