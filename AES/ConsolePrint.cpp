//ConsolePrint.cpp
//Print Text or Hex data in console (or command prompt) with on-off mode

#include "ConsolePrint.h"

#include <iostream>
#include <iomanip>

ConsolePrint::ConsolePrint() : is_printable(true)
{
}


ConsolePrint::~ConsolePrint()
{
}

void ConsolePrint::setMode(mode m)
{
	is_printable = static_cast<bool>(m);
}

void ConsolePrint::print(std::string e) const
{
	if (is_printable)
	{
		std::cout << e;
	}
}

void ConsolePrint::printLine() const
{
	if (is_printable)
	{
		std::cout << std::endl;
	}
}

void ConsolePrint::printLine(std::string e) const
{
	if (is_printable)
	{
		std::cout << e << std::endl;
	}
}

void ConsolePrint::printHex(unsigned char e) const
{
	if (is_printable)
	{
		std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(e);
	}
}