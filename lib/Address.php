<?php
namespace libp2p;

use Aimeos\Map;

class Address {
	const PROTOCOLS = [
		'ip4'   => [ 4, 32 ],
		'tcp'   => [ 6, 16 ],
		'ws'    => [ 477, 0 ],
		'http'  => [ 480, 0 ],
	];

	private array $protocols;

	public function __construct( $address ) {
		$address = explode( '/', trim( $address, '/' ) );

		$protocols = Map::from( self::PROTOCOLS );

		$protocol = null;
		foreach ( $address as $i => $part ) :
			if ( is_null( $protocol ) ) {
				if ( ! $protocol = $protocols->get( $part ) ) {
					throw new \InvalidArgumentException( "Unknown protocol: $part" );
				}
				$protocol = $part;
			} else {
				$this->protocols[] = [
					'name'  => $protocol,
					'value' => $part,
				];
				$protocol = null;
			}
		endforeach;

		if ( $protocol ) {
			$this->protocols[] = [
				'name'  => $protocol,
				'value' => null,
			];
		}
	}

	public function get_protocols() {
		return $this->protocols;
	}
}
