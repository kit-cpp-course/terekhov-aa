#include "pch.h"
#include "FIle.h"

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
