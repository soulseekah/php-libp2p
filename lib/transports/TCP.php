<?php
namespace libp2p\Transports;

use libp2p\{Node, Address, Listener, Listeners};

class TCP extends \libp2p\Transport {
	public static function create_listener( Node $node, Address $address ) : Listener {
		return new Listeners\TCP( __CLASS__, $node, $address );
	}
}
