<?php namespace ProcessWire;

final class Rs256Signer implements SignerInterface {

    public function getAlgorithm(): string {
        return 'RS256';
    }

    public function sign(string $data, array $options): string {
        if (!function_exists('openssl_sign')) {
            throw new \RuntimeException('TokenForge: OpenSSL extension is required for RS256 signing.');
        }

        $privateKey = isset($options['private_key']) ? (string)$options['private_key'] : '';
        if ($privateKey === '') {
            throw new WireException('TokenForge: RS256 requires private_key or private_key_path.');
        }

        $passphrase = isset($options['private_key_password']) ? (string)$options['private_key_password'] : '';
        $resource = @openssl_pkey_get_private($privateKey, $passphrase);
        if ($resource === false) {
            throw new WireException('TokenForge: Invalid private key for RS256.');
        }

        if (!@openssl_sign($data, $signature, $resource, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('TokenForge: Failed to sign JWT.');
        }

        return Base64Url::encode($signature);
    }
}
