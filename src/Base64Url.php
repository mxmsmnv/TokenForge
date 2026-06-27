<?php namespace ProcessWire;

final class Base64Url {

    public static function encode(string $value): string {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    public static function decode(string $value): string {
        $pad = strlen($value) % 4;
        if ($pad > 0) $value .= str_repeat('=', 4 - $pad);
        return base64_decode(strtr($value, '-_', '+/'), true) ?: '';
    }
}

