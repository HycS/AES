//ConsolePrint.h
//Print Text or Hex data in console (or command prompt) with on-off mode

#pragma once

#include <string>

class ConsolePrint
{
public:
	enum class mode
	{
		off,
		on
	};
	ConsolePrint();
	~ConsolePrint();
	void setMode(mode m); //Turn on or off print mode
	void print(std::string e) const; //print Text without endline
	void printLine() const; //print only endline
	void printLine(std::string e) const; //print Text with endline
	void printHex(unsigned char e) const; //print Hex
private:
	bool is_printable;
};

