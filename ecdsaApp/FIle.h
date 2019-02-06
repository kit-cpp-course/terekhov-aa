#pragma once
#include <string>
#include <fstream>
#include <streambuf>
#include <sstream>
#include <iostream>
#include <vector>
#include <set>

class FIle
{
protected: 
public:
	static std::string getFileData(std::string path);
	static bool CreateFile(std::string path, std::string data);
	static std::vector<std::string> splitpath(const std::string& str, const std::set<char> delimiters);
	FIle();
	~FIle();
};

