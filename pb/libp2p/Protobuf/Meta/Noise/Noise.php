<?php
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: pb/noise.proto

namespace libp2p\Protobuf\Meta\Noise;

class Noise
{
    public static $is_initialized = false;

    public static function initOnce() {
        $pool = \Google\Protobuf\Internal\DescriptorPool::getGeneratedPool();

        if (static::$is_initialized == true) {
          return;
        }
        $pool->internalAddGeneratedFile(
            '
�
pb/noise.proto"Z
HandshakePayload
identity_key (
identity_sig (
data (H �B
_dataB5�libp2p\\Protobuf\\Noise�libp2p\\Protobuf\\Meta\\Noisebproto3'
        , true);

        static::$is_initialized = true;
    }
}

