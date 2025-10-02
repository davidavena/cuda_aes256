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

	inline std::vector<uint8_t> extractBytes(std::ifstream& inputFile) {
		std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
		return bytes;
	}

	inline void closeFile(std::ifstream& inputFile) {
		inputFile.close();
	}
}