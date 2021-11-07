<?php
namespace libp2p;

use libp2p\Transports;

abstract class Transport {
	public static function create_listener( Node $node, Peer $peer, Address $address ) : Listener {
		$transport_class = Transports\TCP::class;

		$reflector = new \ReflectionMethod( $transport_class, $method = __FUNCTION__ );
		if ( $reflector->getDeclaringClass()->getName() === __CLASS__ ) {
			throw new \BadMethodCallException( "$transport_class does not override ::$method. Loop prevented." );
		}

		return $transport_class::create_listener( $node, $peer, $address );
	}

	public static function dial() : Connection {
	}
}
