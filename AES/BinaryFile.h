//BinaryFile.h
//Read/Write Binary Data From/To File

#pragma once
#include <string>
#include <vector>

class BinaryFile
{
public:
	BinaryFile();
	~BinaryFile();
	void readFromFile(std::string path);
	void writeToFile(std::string path);
	size_t size() const;
	void clear();
	unsigned char& operator[](size_t index);
	std::vector<unsigned char>& get();

private:
	std::string file_path;
	std::vector<unsigned char> byte_array;
};