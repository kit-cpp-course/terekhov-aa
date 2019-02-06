// ecdsaApp.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include "pch.h"
#include "ecdsaApp.h"



int main()
{
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	char command[1024];
	std::cin >> command;
	bool res = controller(command);
	if (res == true) {
		main();
	} else {
		return 0;
	}
	
}

bool controller(char command[])
{
	std::regex regex("(encryptFIle|discriptFIle)<(.*)>");

	const int ACTION_PART = 0;
	const int PATH_PART = 1;

	std::cmatch cm;

	std::string strCommand = std::string(command); //todo исправить

	Encryptor * encryptor = new Encryptor();

	
	if (strCommand == "help") {
		std::cout << "Вы используете учебное приложение для создания ключей, шифрования и дешифрование файла.\nСоздайте текстовый документ в формате .txt в отдельной папке и напишите полный путь до него.\nsetFilePath<путь/до/файла/шифрования> //писать с угловыми скобками\n";
	}
	else if (strCommand == "createKeys") {
		std::cout << "Введите пароль";
		std::string key;
		std::cin >> key;
		encryptor->CreateKeys(key);
	}
	else if (regex_match(command, cm, regex)) {

		std::string fileData = FIle::getFileData(cm[PATH_PART]);
		DWORD                   KeyBlobLength = 0;
		DWORD                   SignatureBlobLength = 0;

		PBYTE                   KeyBlob = NULL;
		PBYTE                   data = NULL;
		PBYTE                   SignatureBlob = NULL;


		if (cm[ACTION_PART] == "encryptFIle")
		{
			data = encryptor->SignHash(
				(PBYTE)fileData.c_str(),
				sizeof(fileData.c_str()),
				&SignatureBlob,
				&SignatureBlobLength,
				&KeyBlob,
				&KeyBlobLength);
			FIle::CreateFile(cm[PATH_PART], std::string((char *)data));
		}
		else if (cm[ACTION_PART] == "discriptFIle")
		{
			encryptor->VerifySignature(
				(PBYTE)fileData.c_str(),
				sizeof(fileData.c_str()),
				SignatureBlob,
				SignatureBlobLength,
				KeyBlob,
				KeyBlobLength);
		}

		std::cout << "Действие было успешно произвидено";
	}
	else if (strCommand == (char *)"exit")
	{
		return false;
	}
	else {
		std::cout << "Команда была не найдена, напишите help что бы получить подробную информацию";
	}
	return true;
}

// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
