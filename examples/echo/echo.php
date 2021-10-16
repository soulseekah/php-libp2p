<?php
include __DIR__ . "/../../vendor/autoload.php";

use Aimeos\Map;

$args = Map::from( getopt( 'p:', [ 'dial:', 'transport:' ] ) );

$port      = $args->get( 'p', 10333 );
$dial      = (array) $args->get( 'dial' );
$transport = $args->get( 'transport' );

$peer = new libp2p\Peer();
$node = new libp2p\Node( $peer, [
	'addresses' => [
		'listen' => [
			"/ip4/0.0.0.0/tcp/$port/$transport",
		],
	],
] );

$node->handle( '/echo/1.0', function( $message ) {
} );

$node->start();
