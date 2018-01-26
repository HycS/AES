//AES16.cpp
//Processing AES-128 Encryption with 16Bytes(128-bit) data

#include "AES16.h"

//constructInvSBox() will fill rest of table
static unsigned char SBox[2][256] = {
	{
	0xD4, 0xAD, 0x82, 0x7D, 0xA2, 0x59, 0xF0, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xCA, 0xC9, 0xFA, 0x47,
	0xA5, 0x34, 0xFD, 0x26, 0xE5, 0x3F, 0xCC, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0xB7, 0x93, 0x36, 0xF7,
	0xD3, 0xC2, 0x32, 0x0A, 0xAC, 0x06, 0x5C, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE0, 0x3A, 0x49, 0x24,
	0x12, 0x07, 0xC7, 0xC3, 0x80, 0x96, 0x9A, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x04, 0x23, 0x18, 0x05,
	0x01, 0x30, 0x7C, 0x7B, 0x67, 0x6B, 0xC5, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0x63, 0x77, 0xF2, 0x6F,
	0x1E, 0x9B, 0xF8, 0x11, 0x87, 0xD9, 0x94, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0xE1, 0x98, 0x69, 0x8E,
	0xCB, 0x6A, 0xD1, 0xED, 0xBE, 0xFC, 0x5B, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0x53, 0x00, 0x20, 0xB1,
	0xB6, 0xBC, 0xA3, 0x8F, 0xDA, 0x9D, 0xF5, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0x51, 0x40, 0x92, 0x38,
	0xA7, 0xC4, 0x0C, 0xEC, 0x7E, 0x97, 0x17, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0xCD, 0x13, 0x5F, 0x44,
	0x56, 0x6C, 0xC8, 0x6D, 0xF4, 0xD5, 0xA9, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xE7, 0x37, 0x8D, 0x4E,
	0x99, 0x41, 0xA1, 0x0D, 0x2D, 0xE6, 0x68, 0x0F, 0xB0, 0x54, 0xBB, 0x16, 0x8C, 0x89, 0xBF, 0x42,
	0xEE, 0x46, 0x81, 0xDC, 0xB8, 0x2A, 0x88, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0x60, 0x4F, 0x22, 0x90,
	0xDD, 0xE8, 0x78, 0x2E, 0x74, 0xA6, 0xC6, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0xBA, 0x25, 0x1C, 0xB4,
	0x35, 0x61, 0x3E, 0x66, 0x57, 0x03, 0x0E, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0x70, 0xB5, 0x48, 0xF6,
	0xF9, 0x45, 0xEF, 0xFB, 0x02, 0x4D, 0x85, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0xD0, 0xAA, 0x43, 0x33,
	0x3B, 0x52, 0x83, 0x1A, 0xD6, 0x6E, 0xA0, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x09, 0x2C, 0x1B, 0x5A
	},
	{ 0 }
};

//constructRCon() will fill table
static unsigned char rcon[11] = { 0 };

//constructGMul() will fill table
static unsigned char GMul2[256] = { 0 };
static unsigned char GMul3[256] = { 0 };
static unsigned char GMul9[256] = { 0 };
static unsigned char GMul11[256] = { 0 };
static unsigned char GMul13[256] = { 0 };
static unsigned char GMul14[256] = { 0 };

AES16::AES16(const std::vector<unsigned char>& key_text, const std::vector<unsigned char>& plain_text) : current_round(0), round_keys()
{
	key.assign(key_text.cbegin(), key_text.cend());
	byte_array.assign(plain_text.cbegin(), plain_text.cend());

	//input size check
	if (key.size() != 16 || byte_array.size() != 16)
	{
		throw -1;
	}
	constructInvSBox();
	constructRCon();
	constructGMul();
}

AES16::~AES16()
{
}

void AES16::encrypt()
{
	cp.setMode(ConsolePrint::mode::on);
	generateRoundKey(AES16::mode::direct);

	cp.printLine("ROUND 0");
	current_round = 0;
	addRoundKey(0);
	for (int i = 1; i <= 9; ++i)
	{
		cp.printLine("ROUND " + std::to_string(i));
		current_round = i;
		subByte(AES16::mode::direct);
		shiftRow(AES16::mode::direct);
		mixColumn_wT(AES16::mode::direct);
		addRoundKey(i);
	}
	cp.printLine("ROUND 10");
	current_round = 10;
	subByte(AES16::mode::direct);
	shiftRow(AES16::mode::direct);
	addRoundKey(10);
}

void AES16::decrypt()
{
	cp.setMode(ConsolePrint::mode::off);
	generateRoundKey(AES16::mode::inverse);

	current_round = 0;
	addRoundKey(0);
	for (int i = 1; i <= 9; ++i)
	{
		current_round = i;
		subByte(AES16::mode::inverse);
		shiftRow(AES16::mode::inverse);
		mixColumn_wT(AES16::mode::inverse);
		addRoundKey(i);
	}
	current_round = 10;
	subByte(AES16::mode::inverse);
	shiftRow(AES16::mode::inverse);
	addRoundKey(10);
}

std::vector<unsigned char>& AES16::get()
{
	return byte_array;
}

void AES16::constructInvSBox()
{
	for (int i = 0; i < 256; ++i)
	{
		SBox[static_cast<int>(AES16::mode::inverse)][SBox[static_cast<int>(AES16::mode::direct)][i]] = i;
	}
}

void AES16::constructGMul()
{
	for (int i = 0; i < 256; ++i)
	{
		GMul2[i] = GMul(2, i);
		GMul3[i] = GMul(3, i);
		GMul9[i] = GMul(9, i);
		GMul11[i] = GMul(11, i);
		GMul13[i] = GMul(13, i);
		GMul14[i] = GMul(14, i);
	}
}

void AES16::constructRCon()
{
	rcon[0] = 0b10001101;
	for (int i = 1; i < 11; ++i)
	{
		rcon[i] = GMul(2, rcon[i - 1]);
	}
}

void AES16::subByte(mode t)
{
	
	cp.print("SB : ");
	for (int i = 0; i < 16; ++i)
	{
		byte_array[i] = SBox[static_cast<int>(t)][byte_array[i]];
		cp.printHex(byte_array[i]);
	}
	cp.printLine();
}
void AES16::shiftRow(mode t)
{
	/*
	 * 0x00 0x01 0x02 0x03
	 * 0x04 0x05 0x06 0x07
	 * 0x08 0x09 0x0A 0x0B
	 * 0x0C 0x0D 0x0E 0x0F
	 * ^^^^^^^^^^^^^^^^^^  mode::inverse
	 * ||||||||||||||||||
	 * vvvvvvvvvvvvvvvvvv  mode::direct
	 * 0x00 0x0D 0x0A 0x07
	 * 0x04 0x01 0x0E 0x0B 
	 * 0x08 0x05 0x02 0x0F 
	 * 0x0C 0x09 0x06 0x03
	 */
	static const unsigned char si[2][16] = { { 0x00, 0x0D, 0x0A, 0x07, 0x04, 0x01, 0x0E, 0x0B, 0x08, 0x05, 0x02, 0x0F, 0x0C, 0x09, 0x06, 0x03 },
											 { 0x00, 0x05, 0x0A, 0x0F, 0x04, 0x09, 0x0E, 0x03, 0x08, 0x0D, 0x02, 0x07, 0x0C, 0x01, 0x06, 0x0B } };
	static std::vector<unsigned char> temp(16, 0x00);

	for (int i = 0; i < 16; ++i)
	{
		temp[i] = byte_array[si[static_cast<int>(t)][i]];
	}
	cp.print("SR : ");
	for (int i = 0; i < 16; ++i)
	{
		byte_array[i] = temp[i];
		cp.printHex(byte_array[i]);
	}
	cp.printLine();
}
void AES16::addRoundKey(int key_index)
{
	cp.print("AR : ");

	for (int i = 0; i < 4; ++i)
	{
		byte_array[i * 4 + 0] = byte_array[i * 4 + 0] ^ round_keys[key_index][i][0];
		byte_array[i * 4 + 1] = byte_array[i * 4 + 1] ^ round_keys[key_index][i][1];
		byte_array[i * 4 + 2] = byte_array[i * 4 + 2] ^ round_keys[key_index][i][2];
		byte_array[i * 4 + 3] = byte_array[i * 4 + 3] ^ round_keys[key_index][i][3];
		cp.printHex(byte_array[i * 4 + 0]);
		cp.printHex(byte_array[i * 4 + 1]);
		cp.printHex(byte_array[i * 4 + 2]);
		cp.printHex(byte_array[i * 4 + 3]);
	}
	cp.printLine();
}
void AES16::mixColumn(mode t)
{
	// r0 = 2*a0 + 3*a1 + a2   + a3
	// r1 = a0   + 2*a1 + 3*a2 + a3
	// r2 = a0   + a1   + 2*a2 + 3*a3
	// r3 = 3*a0 + a1   + a2   + 2*a3

	//Inverse
	// r0 = 14*a0 + 11*a1 + 13*a2 +  9*a3
	// r1 =  9*a0 + 14*a1 + 11*a2 + 13*a3
	// r2 = 13*a0 +  9*a1 + 14*a2 + 11*a3
	// r3 = 11*a0 + 13*a1 +  9*a2 + 14*a3
	cp.print("MC : ");
	word origin, res;

	for (int i = 0; i < 16; i += 4)
	{
		origin[0] = byte_array[0 + i];
		origin[1] = byte_array[1 + i];
		origin[2] = byte_array[2 + i];
		origin[3] = byte_array[3 + i];

		// 0x1B ==  b00011011
		res[0] = (byte_array[0 + i] << 1) ^ (0x1b & (static_cast<unsigned char>(static_cast<signed char>(byte_array[0 + i]) >> 7)));
		res[1] = (byte_array[1 + i] << 1) ^ (0x1b & (static_cast<unsigned char>(static_cast<signed char>(byte_array[1 + i]) >> 7)));
		res[2] = (byte_array[2 + i] << 1) ^ (0x1b & (static_cast<unsigned char>(static_cast<signed char>(byte_array[2 + i]) >> 7)));
		res[3] = (byte_array[3 + i] << 1) ^ (0x1b & (static_cast<unsigned char>(static_cast<signed char>(byte_array[3 + i]) >> 7)));

		byte_array[0 + i] = res[0] ^ origin[3] ^ origin[2] ^ res[1] ^ origin[1]; //2,3,1,1
		byte_array[1 + i] = res[1] ^ origin[0] ^ origin[3] ^ res[2] ^ origin[2]; //1,2,3,1
		byte_array[2 + i] = res[2] ^ origin[1] ^ origin[0] ^ res[3] ^ origin[3]; //1,1,2,3
		byte_array[3 + i] = res[3] ^ origin[2] ^ origin[1] ^ res[0] ^ origin[0]; //3,1,1,2

		cp.printHex(byte_array[0 + i]);
		cp.printHex(byte_array[1 + i]);
		cp.printHex(byte_array[2 + i]);
		cp.printHex(byte_array[3 + i]);
	}
	cp.printLine();
}

void AES16::mixColumn_wT(mode t)
{
	// * : GMul, +: XOR

	// r0 = 2*a0 + 3*a1 + a2   + a3
	// r1 = a0   + 2*a1 + 3*a2 + a3
	// r2 = a0   + a1   + 2*a2 + 3*a3
	// r3 = 3*a0 + a1   + a2   + 2*a3

	//Inverse
	// r0 = 14*a0 + 11*a1 + 13*a2 +  9*a3
	// r1 =  9*a0 + 14*a1 + 11*a2 + 13*a3
	// r2 = 13*a0 +  9*a1 + 14*a2 + 11*a3
	// r3 = 11*a0 + 13*a1 +  9*a2 + 14*a3
	cp.print("MC : ");
	word origin, res;

	if (t == mode::direct)
	{
		for (int i = 0; i < 16; i += 4)
		{
			origin[0] = byte_array[0 + i];
			origin[1] = byte_array[1 + i];
			origin[2] = byte_array[2 + i];
			origin[3] = byte_array[3 + i];

			byte_array[0 + i] = GMul2[origin[0]] ^ GMul3[origin[1]] ^ origin[2] ^ origin[3]; //2,3,1,1
			byte_array[1 + i] = origin[0] ^ GMul2[origin[1]] ^ GMul3[origin[2]] ^ origin[3]; //1,2,3,1
			byte_array[2 + i] = origin[0] ^ origin[1] ^ GMul2[origin[2]] ^ GMul3[origin[3]]; //1,1,2,3
			byte_array[3 + i] = GMul3[origin[0]] ^ origin[1] ^ origin[2] ^ GMul2[origin[3]]; //3,1,1,2

			cp.printHex(byte_array[0 + i]);
			cp.printHex(byte_array[1 + i]);
			cp.printHex(byte_array[2 + i]);
			cp.printHex(byte_array[3 + i]);
		}
	}
	else if (t == mode::inverse)
	{
		for (int i = 0; i < 16; i += 4)
		{
			origin[0] = byte_array[0 + i];
			origin[1] = byte_array[1 + i];
			origin[2] = byte_array[2 + i];
			origin[3] = byte_array[3 + i];

			byte_array[0 + i] = GMul14[origin[0]] ^ GMul11[origin[1]] ^ GMul13[origin[2]] ^ GMul9[origin[3]];
			byte_array[1 + i] = GMul9[origin[0]] ^ GMul14[origin[1]] ^ GMul11[origin[2]] ^ GMul13[origin[3]];
			byte_array[2 + i] = GMul13[origin[0]] ^ GMul9[origin[1]] ^ GMul14[origin[2]] ^ GMul11[origin[3]];
			byte_array[3 + i] = GMul11[origin[0]] ^ GMul13[origin[1]] ^ GMul9[origin[2]] ^ GMul14[origin[3]];

			cp.printHex(byte_array[0 + i]);
			cp.printHex(byte_array[1 + i]);
			cp.printHex(byte_array[2 + i]);
			cp.printHex(byte_array[3 + i]);
		}
	}
	else
	{
		throw -1;
	}

	cp.printLine();
}

void AES16::mixColumn_wT(state& input, mode t) const
{
	// * : GMul, +: XOR

	// r0 = 2*a0 + 3*a1 + a2   + a3
	// r1 = a0   + 2*a1 + 3*a2 + a3
	// r2 = a0   + a1   + 2*a2 + 3*a3
	// r3 = 3*a0 + a1   + a2   + 2*a3

	//Inverse
	// r0 = 14*a0 + 11*a1 + 13*a2 +  9*a3
	// r1 =  9*a0 + 14*a1 + 11*a2 + 13*a3
	// r2 = 13*a0 +  9*a1 + 14*a2 + 11*a3
	// r3 = 11*a0 + 13*a1 +  9*a2 + 14*a3
	cp.print("MC : ");
	word origin, res;

	if (t == mode::direct)
	{
		for (int i = 0; i < 4; ++i)
		{
			for (int k = 0; k < 4; ++k)
			{
				origin[k] = input[i][k];
			}
			input[i][0] = GMul2[origin[0]] ^ GMul3[origin[1]] ^ origin[2] ^ origin[3];
			input[i][1] = origin[0] ^ GMul2[origin[1]] ^ GMul3[origin[2]] ^ origin[3];
			input[i][2] = origin[0] ^ origin[1] ^ GMul2[origin[2]] ^ GMul3[origin[3]];
			input[i][3] = GMul3[origin[0]] ^ origin[1] ^ origin[2] ^ GMul2[origin[3]];

			cp.printHex(input[i][0]);
			cp.printHex(input[i][1]);
			cp.printHex(input[i][2]);
			cp.printHex(input[i][3]);
		}
	}
	else if (t == mode::inverse)
	{
		for (int i = 0; i < 4; ++i)
		{
			for (int k = 0; k < 4; ++k)
			{
				origin[k] = input[i][k];
			}
			input[i][0] = GMul14[origin[0]] ^ GMul11[origin[1]] ^ GMul13[origin[2]] ^ GMul9[origin[3]];
			input[i][1] = GMul9[origin[0]] ^ GMul14[origin[1]] ^ GMul11[origin[2]] ^ GMul13[origin[3]];
			input[i][2] = GMul13[origin[0]] ^ GMul9[origin[1]] ^ GMul14[origin[2]] ^ GMul11[origin[3]];
			input[i][3] = GMul11[origin[0]] ^ GMul13[origin[1]] ^ GMul9[origin[2]] ^ GMul14[origin[3]];

			cp.printHex(input[i][0]);
			cp.printHex(input[i][1]);
			cp.printHex(input[i][2]);
			cp.printHex(input[i][3]);
		}
	}
	else
	{
		throw - 1;
	}

	cp.printLine();
}

AES16::word AES16::func_g(int index, word& input) const
{
	word temp_word;
	//RotWord and Subword
	temp_word[0] = SBox[static_cast<int>(mode::direct)][input[1]];
	temp_word[1] = SBox[static_cast<int>(mode::direct)][input[2]];
	temp_word[2] = SBox[static_cast<int>(mode::direct)][input[3]];
	temp_word[3] = SBox[static_cast<int>(mode::direct)][input[0]];
	//Rcon
	temp_word[0] = temp_word[0] ^ rcon[index];
	return temp_word;
}

void AES16::generateRoundKey(mode t)
{
	word key_words[11 * 4];
	word temp_word;

	if (t == mode::direct)
	{
		//Initialize First Key
		for (int i = 0; i < 4; ++i)
		{
			for (int k = 0; k < 4; ++k)
			{
				key_words[i][k] = key[i * 4 + k];
			}
		}

		for (int i = 4; i < 11 * 4; i += 4)
		{
			temp_word[0] = key_words[i - 1][0];
			temp_word[1] = key_words[i - 1][1];
			temp_word[2] = key_words[i - 1][2];
			temp_word[3] = key_words[i - 1][3];

			temp_word = func_g(i / 4, temp_word); //z value

			key_words[i] = key_words[i - 4] ^ temp_word;

			for (int k = 1; k <= 3; ++k)
			{
				key_words[i + k] = key_words[i + k - 1] ^ key_words[i + k - 4];
			}
		}

		for (int i = 0; i < 11; ++i)
		{
			for (int k = 0; k < 4; ++k)
			{
				round_keys[i][k] = key_words[i * 4 + k];
			}
		}
	}
	else if (t == mode::inverse)
	{
		generateRoundKey(mode::direct);

		word temp_round_keys[11][4];
		//reverse round key
		for (int i = 0; i <= 10; ++i)
		{
			for (int k = 0; k <= 3; ++k)
			{
				temp_round_keys[i][k] = round_keys[i][k];
			}
		}
		for (int i = 0; i <= 10; ++i)
		{
			for (int k = 0; k < 4; ++k)
			{
				round_keys[i][k] = temp_round_keys[10 - i][k];
			}
		}
		//Inverse Mix Columns
		for (int i = 1; i <= 9; ++i)
		{
			state temp_state(round_keys[i][0], round_keys[i][1], round_keys[i][2], round_keys[i][3] );
			mixColumn_wT(temp_state, mode::inverse);

			round_keys[i][0] = temp_state[0];
			round_keys[i][1] = temp_state[1];
			round_keys[i][2] = temp_state[2];
			round_keys[i][3] = temp_state[3];
		}
	}
	else
	{
		throw -1;
	}
}

unsigned char AES16::GMul(unsigned char a, unsigned char b)
{
	unsigned char p = 0;
	unsigned char hi_bit_set = 0;
	for (int i = 0; i < 8; ++i)
	{
		if ((b & 0b00000001) != 0)
		{
			p ^= a;
		}
		hi_bit_set = static_cast<unsigned char>(a & 0b10000000); //check overflow
		a <<= 1;
		if (hi_bit_set != 0)
		{
			a ^= 0b00011011; /* x^8 + x^4 + x^3 + x + 1 */ //If overflow exists, x^8 -> add(XOR) 0b00011011
		}
		b >>= 1;
	}
	return p;
}