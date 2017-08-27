<?php

class PGK_JWT{
	
	private $header = [];
	private $payload = [];
	private $key = '';
	private $signature = '';
	private $algorithm_supported = ['HS256'];

	public function __construct($header,$payload,$key){
		
		$this->header = $header;

		$this->payload = $payload;

		$this->key = $key;

	}

	/*
	* Gera o token com base nas informações recebidas
	*/
	public function generate_token(){
		
		try {
			$this->__check_info();

			$h = base64_encode($this->header);
			$p = base64_encode($this->payload);

			$this->signature = hash_hmac('sha256', "$h.$p", $this->key);
			$this->signature = base64_encode($this->signature);

			$token = "$h.$p.$this->signature";

			return $token;	

		} catch (Exception $e) {

			return array('error' => true, 'message' => $e);

		}
		
	}

	/*
	* Check para verificar se as informações passadas são válidas
	*/
	private function __check_info(){

		if(!in_array_keys('alg',$this->header) || !in_array_keys('typ',$this->header)){
			throw new Exception("Header must have alg and typ fields", 1);
			
		}

		if(in_array($header['algo'], $this->algorithm_supported)){
			throw new Exception("Algorithm no supported", 1);
			
		}
		

	}

}