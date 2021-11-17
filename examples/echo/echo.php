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

$node->log->pushHandler(
	new Monolog\Handler\StreamHandler( STDOUT ),
	$node->log::DEBUG
);

$node->handle( '/echo/1.0.0', function( string $message, libp2p\Mplex\Stream $stream, libp2p\Peer $peer, libp2p\Node $node ) {
	$stream->send( $message );
} );

$node->start();
