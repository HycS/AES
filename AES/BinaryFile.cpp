//BinaryFile.h
//Read/Write Binary Data From/To File

#include "BinaryFile.h"

#include <iostream>
#include <fstream>

BinaryFile::BinaryFile()
{
}

BinaryFile::~BinaryFile()
{
}

void BinaryFile::readFromFile(std::string path)
{
	file_path = path;
	std::ifstream ifs;
	try
	{
		ifs.open(path, std::ifstream::in | std::ifstream::binary | std::ifstream::ate);
	}
	catch (std::exception& e)
	{
		std::cout << e.what() << std::endl;
		return;
	}
	
	std::fstream::pos_type input_file_size = ifs.tellg();
	ifs.seekg(ifs.beg);
	byte_array.assign(static_cast<unsigned int>(input_file_size), 0);
	
	ifs.read(reinterpret_cast<char*>(&byte_array[0]), input_file_size);
	ifs.close();

}

void BinaryFile::writeToFile(std::string path)
{
	std::ofstream ofs;
	ofs.open(path, std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);
	ofs.write(reinterpret_cast<char*>(&byte_array[0]), byte_array.size());
	ofs.close();
}

size_t BinaryFile::size() const
{
	return byte_array.size();
}

void BinaryFile::clear()
{
	file_path.clear();
	byte_array.clear();
}

unsigned char& BinaryFile::operator[](size_t index)
{
	return byte_array.at(index);
}

std::vector<unsigned char>& BinaryFile::get()
{
	return byte_array;
}