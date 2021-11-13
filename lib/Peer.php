<?php
namespace libp2p;

use libp2p\Protobuf;

class Peer {
	public function __construct() {
		// $this->keypair = Crypto::generate_keypair();
		$this->keypair['public'] = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy2WXBnG3uLqzAVZXB4Dd
H6QcpmPsXK9eHsL2phu9EGTgydYfbJY5RMWe28i4qkQd0oxm36WdRcHs58DcVrVq
Yx5EI01V3qDOBBIA0jTvwoOyjZVNBCb4DyV3hD8nAGV/agEm1SehBAkONFUf+/kr
kqrHS9Ya5htaYaSI7vg+uIC8lqcPVhAC38zKR+SPyr3WA1tzeIOszg9pmTaectYB
3lyDR1szBefeju9v+nMcMol1dXidNNJNTVZ1Mqz417alnVS0ZOSFNSxaaEKF2VOV
9YSo9Wtqrf5WXx+Xjqxf62ph3MIa2GMNbcX/CR11jv22zZ8npkxwL7rWaUza7FgE
3wIDAQAB
-----END PUBLIC KEY-----';
		$this->keypair['private'] = '-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAy2WXBnG3uLqzAVZXB4DdH6QcpmPsXK9eHsL2phu9EGTgydYf
bJY5RMWe28i4qkQd0oxm36WdRcHs58DcVrVqYx5EI01V3qDOBBIA0jTvwoOyjZVN
BCb4DyV3hD8nAGV/agEm1SehBAkONFUf+/krkqrHS9Ya5htaYaSI7vg+uIC8lqcP
VhAC38zKR+SPyr3WA1tzeIOszg9pmTaectYB3lyDR1szBefeju9v+nMcMol1dXid
NNJNTVZ1Mqz417alnVS0ZOSFNSxaaEKF2VOV9YSo9Wtqrf5WXx+Xjqxf62ph3MIa
2GMNbcX/CR11jv22zZ8npkxwL7rWaUza7FgE3wIDAQABAoIBAEI9KGz51co8SxWR
Z7BS4DBwwr/RZOVeWzmLZsX73JudLrOsnvk/BxGFhlGvUaxpmIi8HriQ9+IC4MMs
xNUcKbRz497XTbK+Dbm3nzrV8IsZVqnTSIykoD5WhlC0PGBdrZv5Ggtq534n8M9M
NalaoT0XjuX8qS/tEocgDVQ91jdBaNroM654glx1KUdrB10oOivtvqlnb3sozVqI
N+G+woKVe9y5/egVmnuhJVPD0eQFnTJ0WgPbnAPvx1liSFgdxW+PursJcYbti+dA
pKtYMGGQrRsOt6uS+AoJZlzHyCp0ALhM2s6vU+GMRJKflw51WQDoJ0BlAWKXrZYD
JpJIfakCgYEA77BLNE4cxS4J4bQticv/2TqzryACgGWX/5ktPAKlh9y9P0Y5vGWG
y7EXKFlO/LJfFBRcAEITEQwT/RvkT6I1lWoQS/we3pnSipxUdTX8CoxXQ1WqF+bj
b2RCkpfVLm2wuFmSeubv3HeYxJ4/sN4q/RvJ/j9YKf9Mgc9Np2VxYEsCgYEA2T0K
+BwcWS+ysew+PaK5iJQewgp9ou5k9dQqaZ+Yn1E66ew2xSdrfXvFDZOrYL2xDYAi
l711rJn5UqPYJjMXhDg+NAIAJDvD59keDmIa8HfPXRAoijN+B61TQcxqAefmLAJ6
OsxrzsyymzcDBvvtorjV6l05OLlfRnCPDp1OWT0CgYAmVBqykosnPOV3okhl8KlJ
I4n4RzYfMh/MT8JcBlBSGYppw+EXr2SOzhLV8PIglqV9oIPVxrslzrijkQJBeb73
1a4leHu3PQHeCIG4/JkBVs/dhKVejR1xgqbiqkT8162azTgPTz6sErPrPSMSNXTK
ZNc4QQjoLlsdpvjT+/TVYQKBgQCOlkqE366bu3sG3ZFc01oEE3S82DXuo5sQ39mW
ynJa3+5Ta//nGCCtlHeambp7HQcBXYFXJ7v9NnM3kuNk71QYLPJnIIkHP1Mu8ouP
1UTpYTpyUxDI5VNrppBnN8y8w4GIkXe48EQy0JjK2CjchK9NhxShZ98PJF0s1uSP
KyEp4QKBgQDYXIR1bSXd1TGL8TXEG/dPRYsE50/ZJfaZI4cIr8fn/PyvKQ32Ao2E
gWAnz0zOT7JL+XV8znZzbgo+mNh//ZtkrDm7pAcBdM+UIo4LtQ7MbwA1SCmeK86x
m+LkhJjOttNKoyf/VPfH1TO67zq2mpK4XH/YEcLrKYLiUJ0jvXC4+g==
-----END RSA PRIVATE KEY-----';

		$pb_public = Crypto::marshal( $this->keypair['public'] );
		$this->id = Crypto::multihash(
			$pb_public,
			Crypto::len( $pb_public ) <= 42 ? 'identity': 'sha2-256',
			'base58btc',
		);
	}
}
