#include <iostream>
#include <fstream>
#include <string>
#include <vector>

namespace file {
	inline void openFile(std::ifstream& inputFile, const std::string& filename) {
		inputFile.open(filename, std::ios::binary);
		if (!inputFile) {
			std::cerr << "Error opening file." << std::endl;
		}
	}

	inline std::streamsize getFileSize(std::ifstream& inputFile) {
		inputFile.seekg(0, std::ios::end);
		std::streamsize size = inputFile.tellg();
		inputFile.seekg(0, std::ios::beg);
		return size;
	}

	inline void extractBytes(std::ifstream& inputFile, std::vector<char>& dataVector, std::streamsize filesize) {
		if (!(inputFile.read(dataVector.data(), filesize))) {
			std::cerr << "Error reading file." << std::endl;
			return;
		}
	}

	inline void closeFile(std::ifstream& inputFile) {
		inputFile.close();
	}
}