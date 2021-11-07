<?php
namespace libp2p;

use libp2p\Protobuf;

class Peer {
	public function __construct() {
		$this->keypair = Crypto::generate_keypair();

		$pb_public = Crypto::marshal( $this->keypair['public'] );
		$this->id = Crypto::multihash(
			$pb_public,
			Crypto::len( $pb_public ) <= 42 ? 'identity': 'sha2-256',
			'base58btc',
		);
	}
}
