<?php
namespace libp2p;

class Peer {
	public static function create() {
		$peer = new Peer();
		$peer->keypair = Crypto::generate_keypair();
		return $peer;
	}
}
