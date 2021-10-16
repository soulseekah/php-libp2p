<?php
namespace libp2p;

abstract class Listener {
	public \Monolog\Logger $log;

	public function __construct( $transport, Node $node, Address $address ) {
		$this->log = $node->log->withName( static::class );
	}

	abstract public function listen();
	abstract public function poll();
}
