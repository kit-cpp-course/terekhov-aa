#include "pch.h"
#include "FIle.h"

FIle::FIle()
{
}
/*
	Не используется
*/
std::vector<std::string> FIle::splitpath(const std::string& str
	, const std::set<char> delimiters)
{
	std::vector<std::string> result;

	char const* pch = str.c_str();
	char const* start = pch;
	for (; *pch; ++pch)
	{
		if (delimiters.find(*pch) != delimiters.end())
		{
			if (start != pch)
			{
				std::string str(start, pch);
				result.push_back(str);
			}
			else
			{
				result.push_back("");
			}
			start = pch + 1;
		}
	}
	result.push_back(start);

	return result;
}

bool FIle::CreateFile(std::string path, std::string data)
{
	std::string from = "File.txt";
	std::string to = "SignedFile.txt";

	size_t start_pos = path.find(from);
	if (start_pos == std::string::npos)
		return false;
	path.replace(start_pos, from.length(), to);

	std::ofstream outfile(path);

	outfile << data << std::endl;

	outfile.close();
	return true;
}
std::string FIle::getFileData(std::string path)
{
	std::ifstream t(path);
	t.seekg(0, std::ios::end);
	size_t size = t.tellg();
	std::string data(size, ' ');
	t.seekg(0);
	t.read(&data[0], size);
	return data;
}

FIle::~FIle()
{
}
