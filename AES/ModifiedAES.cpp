//ModifiedAES.cpp
//Process PKCS7 Padding and AES-128 Encryption / Decryption

#include "ModifiedAES.h"

#include "AES16.h"

ModifiedAES::ModifiedAES(std::vector<unsigned char>& key_input, std::vector<unsigned char>& data_input) : key(key_input), data(data_input)
{
}


ModifiedAES::~ModifiedAES()
{
}

std::vector<unsigned char> ModifiedAES::encrypt()
{
	addPadding();

	//Split Original Data by 128-bit and Processing AES-128 Encryption
	for (auto iter = data.begin(); iter != data.end(); std::advance(iter, 16))
	{
		AES16 a(key, std::vector<unsigned char>(iter, iter+16));
		a.encrypt();

		for (auto& e : a.get())
		{
			result.push_back(e);
		}
	}

	return result;
}

std::vector<unsigned char> ModifiedAES::decrypt()
{
	//Split Encrypted Data by 128-bit and Processing AES-128 Decryption
	for (auto iter = data.begin(); iter != data.end(); std::advance(iter, 16))
	{
		AES16 b(key, std::vector<unsigned char>(iter, iter + 16));
		b.decrypt();

		for (auto& e : b.get())
		{
			result.push_back(e);
		}
	}

	removePadding();
	return result;
}

std::vector<unsigned char>& ModifiedAES::get()
{
	return result;
}

void ModifiedAES::addPadding()
{
	int remain = 16 - static_cast<int>(data.size()) % 16;

	for (int i = 0; i < remain; ++i)
	{
		data.push_back(static_cast<unsigned char>(remain));
	}
}

void ModifiedAES::removePadding()
{
	size_t size = result.size();
	int padding_size = static_cast<int>(result[size - 1]);

	if (padding_size > 16)
	{
		throw -1;
	}
	else
	{
		for (int i = 0; i < padding_size; ++i)
		{
			result.pop_back();
		}
	}
}