//ModifiedAES.h
//Process PKCS7 Padding and AES-128 Encryption / Decryption

#pragma once
#include <vector>

class ModifiedAES
{
public:
	ModifiedAES(std::vector<unsigned char>& key_input, std::vector<unsigned char>& data_input);
	~ModifiedAES();
	std::vector<unsigned char> encrypt(); //AES-128 Encryption
	std::vector<unsigned char> decrypt(); //AES-128 Decryption
	std::vector<unsigned char>& get(); //Reference of result data
private:
	std::vector<unsigned char> key; //128-bit Key
	std::vector<unsigned char> data; //Input Data
	std::vector<unsigned char> result; //Encrypted or Decrypted data
	void addPadding(); //Add PKCS7 Padding
	void removePadding(); //Remove PKCS7 Padding
};

