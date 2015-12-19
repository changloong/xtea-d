module openssl_test;

private import deimos.openssl.evp;
private import core.atomic;

/*
openssl enc -aes-256-cbc -pass pass:MYPASSWORD -P
EVP_CIPHER_CTX_set_key_length(&cipher_ctx, cast(int) password.length );
cipher_type = EVP_aes_256_cbc();
*/

static shared openssl_inited = 1 ;

ubyte[]  openssl_crypt(bool encode)(inout(ubyte)[] data, string method, string  password, ref int errno) {
	errno	= 0 ;
	if ( data.length is 0) {
		errno	= __LINE__ ;
		return null ;
	}
	
	ubyte[63] tmp = 0 ;
	
	if(method !is null){
		if( method.length < 1 || method.length > 63 ) {
			errno	= __LINE__ ;
			return null ;
		}
		for(int i = 0;  i < method.length; i++){
			tmp[i]	= method[i] ;
		}
	}
	
	if( atomicLoad(openssl_inited) ) {
		atomicStore(openssl_inited, 0);
		OpenSSL_add_all_ciphers();
	}
	
	auto cipher_type = method is null ? EVP_aes_256_cbc() : EVP_get_cipherbyname( cast(const(char)*) tmp.ptr );
	
	if (!cipher_type) {
		errno	= __LINE__ ;
		return null ;
	}
	
	auto key_len = EVP_CIPHER_key_length(cipher_type) ;
	auto iv_len = EVP_CIPHER_iv_length(cipher_type);
	
	if ( password.length > key_len ) {
		errno	= __LINE__ ;
		return null ;
	}
	
	if ( password.length < 4 ) {
		errno	= __LINE__ ;
		return null ;
	}
	
	scope key	= new ubyte[ ( password.length > key_len  ? password.length  : key_len ) + 1 ] ;
	scope iv	= new ubyte[ iv_len + 1 ] ;
	const(ubyte*) salt = null ;
	auto derived_key_len	= EVP_BytesToKey(cipher_type, EVP_md5, salt, cast(const(ubyte)*) password.ptr, cast(int) password.length, 1, key.ptr, iv.ptr );
	if( derived_key_len > 32 ) {
		errno	= __LINE__ ;
		return null ;
	}
	
	int outlen   = cast(int) data.length  + EVP_CIPHER_block_size(cipher_type);
	auto outbuf  = new ubyte[ outlen + 1 ] ;
	
	int options = 0 ;
	EVP_CIPHER_CTX cipher_ctx ;
	static if( encode ) {
		EVP_EncryptInit(&cipher_ctx, cipher_type, null, null);
	} else {
		EVP_DecryptInit(&cipher_ctx, cipher_type, null, null);
	}
	scope(exit){
		EVP_CIPHER_CTX_cleanup(&cipher_ctx) ;
	}
	
	static if( encode ) {
		EVP_EncryptInit_ex(&cipher_ctx, null, null, cast(const(ubyte)*) &key[0] , cast(const(ubyte)*) &iv[0] );
	} else {
		EVP_DecryptInit_ex(&cipher_ctx, null, null, cast(const(ubyte)*) &key[0] , cast(const(ubyte)*) &iv[0] );
	}
	
	if ( options  /*& OPENSSL_ZERO_PADDING */ ) {
		EVP_CIPHER_CTX_set_padding(&cipher_ctx, 0);
	}
	
	int i	= 0 ;
	static if( encode ) {
		EVP_EncryptUpdate(&cipher_ctx, &outbuf[0] , &i , &data[0], cast(int) data.length );
	} else {
		EVP_DecryptUpdate(&cipher_ctx, &outbuf[0] , &i , &data[0], cast(int) data.length );
	}
	outlen = i ;
	
	static if( encode ) {
		auto final_ret	= EVP_EncryptFinal(&cipher_ctx, &outbuf [i], &i) ;
	} else {
		auto final_ret	= EVP_DecryptFinal(&cipher_ctx, &outbuf [i], &i) ;
	}
	
	if ( !final_ret ) {
		errno	= __LINE__ ;
		return null ;
	}
	
	outlen += i;
	outbuf[ outlen ] = 0 ;
	
	return outbuf[ 0 .. outlen ] ;
}

alias openssl_encrypt = openssl_crypt!(true) ;
alias openssl_decrypt = openssl_crypt!(false) ;

unittest {
	auto method	= "aes-256-cbc" ;
	auto input	= cast(ubyte[]) "test data here" ;
	auto password	=  "password" ;
	int errno;
	auto data	= openssl_encrypt( input, method , password , errno) ;
	assert(errno is 0);
	assert( openssl_decrypt( data, method , password, errno ) == input );
}
