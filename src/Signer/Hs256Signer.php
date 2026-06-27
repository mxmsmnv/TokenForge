<?php namespace ProcessWire;

final class Hs256Signer implements SignerInterface {

    public function getAlgorithm(): string {
        return 'HS256';
    }

    public function sign(string $data, array $options): string {
        $secret = isset($options['secret']) ? (string)$options['secret'] : '';
        if ($secret === '') {
            throw new WireException('TokenForge: HS256 requires secret.');
        }

        $signature = hash_hmac('sha256', $data, $secret, true);
        return Base64Url::encode($signature);
    }
}

