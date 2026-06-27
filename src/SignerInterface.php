<?php namespace ProcessWire;

interface SignerInterface {
    public function getAlgorithm(): string;
    public function sign(string $data, array $options): string;
}

