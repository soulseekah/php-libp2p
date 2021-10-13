all: composer protobuf

composer:
	composer install

protobuf:
	protoc --php_out=pb/ pb/*.proto

clean:
	rm composer.lock
	rm -rf vendor
	rm -rf pb/libp2p/
