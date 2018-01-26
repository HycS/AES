//main.cpp
//main

#include <iostream>
#include <iomanip>
#include <string>

#include "BinaryFile.h"
#include "ModifiedAES.h"

int main(int argc, char** argv)
{
	const std::string plain_text_path(".\\pt.bin");
	const std::string key_path(".\\key.bin");
	const std::string cipher_text_path(".\\ct.bin");
	const std::string result_text_path(".\\pt2.bin");

	//Read Key File
	BinaryFile key;
	key.readFromFile(key_path);

	//Read Plain Text File
	BinaryFile af;
	af.readFromFile(plain_text_path);

	//Print Key and Plain Text
	std::cout << "[+] key: ";
	for (const auto& e : key.get())
	{
		std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(e);
	}
	std::cout << std::endl;
	std::cout << "[+] Input PlainText: ";
	for (const auto& e : af.get())
	{
		std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(e);
	}
	std::cout << std::endl << std::endl;

	//AES Encrypt
	ModifiedAES maes(key.get(), af.get());
	std::vector<unsigned char> cipher_text = maes.encrypt();

	//Write Encrypted Data to File
	BinaryFile encrypted;
	encrypted.get() = cipher_text;
	encrypted.writeToFile(cipher_text_path);

	//Read Encrypted Data
	BinaryFile ct;
	ct.readFromFile(cipher_text_path);

	//AES Decrypt
	ModifiedAES maes2(key.get(), ct.get());
	std::vector<unsigned char> plain_text = maes2.decrypt();

	//Write Decrypted Data to File
	BinaryFile plain_result;
	plain_result.get() = plain_text;
	plain_result.writeToFile(result_text_path);

	//Print Result
	std::cout << "[+] Result Encryption: ";
	for (const auto& e : cipher_text)
	{
		std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(e);
	}
	std::cout << std::endl;

	std::cout << "[+] Result Decryption: ";
	for (const auto& e : plain_text)
	{
		std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(e);
	}
	std::cout << std::endl;

	return 0;
}