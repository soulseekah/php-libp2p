<?php
include __DIR__ . "/../../vendor/autoload.php";

use Aimeos\Map;

$args = Map::from( getopt( 'p:', [ 'dial:', 'transport:' ] ) );

$port      = $args->get( 'p', 10333 );
$dial      = (array) $args->get( 'dial' );
$transport = $args->get( 'transport' );

$peer = libp2p\Peer::create();
var_dump( $peer );
exit;

$node = new libp2p\Node( $peer, [
	'addresses' => [
		'listen' => [
			"/ip4/0.0.0.0/tcp/$port/$transport",
		],
	],
] );
