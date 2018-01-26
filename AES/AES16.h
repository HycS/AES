//AES16.h
//Processing AES-128 Encryption with 16Bytes(128-bit) data
#pragma once

#include <vector>
#include "ConsolePrint.h"

class AES16
{
private:
	enum class mode
	{
		direct,
		inverse
	};

	//word(4bytes) definition for internal processing
	class word
	{
	public:
		word() :byte{ 0x00, 0x00, 0x00, 0x00 } {}
		word(unsigned char b0, unsigned char b1, unsigned char b2, unsigned char b3) :byte{ b0, b1, b2, b3 } {}
		word(word& rvalue) :byte{ rvalue[0], rvalue[1], rvalue[2], rvalue[3] } {}

		unsigned char& operator[](size_t index) { return byte[index]; }
		word operator^(word& rvalue)
		{
			return word(byte[0] ^ rvalue[0], byte[1] ^ rvalue[1], byte[2] ^ rvalue[2], byte[3] ^ rvalue[3]);
		}
	private:
		unsigned char byte[4];
	};

	//state(4words) definition for internal processing
	class state
	{
	public:
		state() {}
		state(word w0, word w1, word w2, word w3) :w{ w0, w1, w2, w3 } {}
		state(state& rvalue) :w{ rvalue[0], rvalue[1], rvalue[2], rvalue[3] } {}

		word& operator[](size_t index) { return w[index]; }
		state operator^(state& rvalue)
		{
			return state(w[0] ^ rvalue[0], w[1] ^ rvalue[1], w[2] ^ rvalue[2], w[3] ^ rvalue[3]);
		}
	private:
		word w[4];
	};

public:
	AES16(const std::vector<unsigned char>& key_text, const std::vector<unsigned char>& plain_text);
	~AES16();
	void encrypt(); //AES-128 Encryption for 16bytes data
	void decrypt(); //AES-128 Decryption for 16bytes data
	std::vector<unsigned char>& get(); //Reference of result data
private:
	std::vector<unsigned char> byte_array; //Input or Result data
	std::vector<unsigned char> key; //128-bit Key
	word round_keys[11][4]; //Expanded Key Table
	ConsolePrint cp;
	void constructInvSBox(); //Inverse SBox construction
	void constructRCon(); //RCon construction
	void constructGMul(); //Galois Field Multiplication Result Table construction
	void subByte(mode t); //Substitution each byte
	void shiftRow(mode t); //Shift each rows
	void addRoundKey(int key_index); //Add Round key
	void mixColumn(mode t); //Mix Column(NO INVERSE); legacy
	void mixColumn_wT(mode t); //Mix Column with Table
	void mixColumn_wT(state& input, mode t) const; //Mix Column with Table
	word func_g(int index, word& input) const;
	void generateRoundKey(mode t);
	unsigned char GMul(unsigned char a, unsigned char b); //Galois Field Multiplication
	int current_round;
};