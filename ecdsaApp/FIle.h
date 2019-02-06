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
public:
	/*
		Получает строку из текстового файла
	*/
	static std::string getFileData(std::string path);
	/*
		Создает файл и записывает в него строку
	*/
	static bool CreateFile(std::string path, std::string data);
};

