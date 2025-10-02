#include "AESConstants.hpp"

#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <iostream>
#include <array>
#include <vector>
#include <charconv>


namespace aes {
	typedef struct {
		uint32_t word[4] = { 0 };
	} RoundKey;

	typedef struct {
		uint32_t state[4] = { 0 };
	} AESBlock;

	typedef struct {
		RoundKey roundkeys[15] = { 0 };
		uint32_t expandedWords[60] = { 0 };
	} AES256Context;

	


	void generateRoundKeys(AES256Context& context, std::array<uint8_t, 32> bytes);
	

	namespace ecb {

	}

	namespace key_sched {
		std::array<uint32_t, 60> expandWords(std::array<uint8_t, 32> keyBytes);
		static const uint32_t rcon_array[11] = {
			0x00000000,
			0x01000000, 0x02000000, 0x04000000,
			0x08000000, 0x10000000, 0x20000000,
			0x40000000, 0x80000000, 0x1B000000,
			0x36000000
		};
		inline uint32_t rotWord(uint32_t word) {
			return (word << 8) | (word >> 24);
		}
		inline uint32_t rcon(size_t index) {
			return rcon_array[index];
		}
	}
	
	namespace transform {
		void addRoundKey(AESBlock& block, RoundKey roundKey);
		void subBytes(AESBlock& block);
		void shiftRows(AESBlock& block);
		void mixColumns(AESBlock& block);

		void inverseSubBytes(AESBlock& block);
		void inverseShiftRows(AESBlock& block);
		void inverseMixColumns(AESBlock& block);
	}

	namespace util {
		enum mixColumnLookupIndex : uint8_t {
			Hex01 = 0,
			Hex02 = 1,
			Hex03 = 2,

			Hex09 = 0,
			Hex0b = 1,
			Hex0d = 2,
			Hex0e = 3
		};

		uint8_t galoisMulti(uint8_t b1, uint8_t b2);
		uint8_t galoisInverseBrute(uint8_t byte);
		uint8_t affineTransform(uint8_t x);
		uint8_t substituteByteInSBox(uint8_t byte);
		void getBytesFromKeyString(std::array<uint8_t, 32>& bytes, const std::string& key);

		std::vector<uint8_t> parseHexString(const std::string& hexString);

		inline uint32_t extractRow(uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3, uint8_t row) {
			return ((s0 >> (8 * row)) & 0xFF) |
				(((s1 >> (8 * row)) & 0xFF) << 8) |
				(((s2 >> (8 * row)) & 0xFF) << 16) |
				(((s3 >> (8 * row)) & 0xFF) << 24);
		}

		inline void rowScatter(uint32_t row, int r, uint32_t& s0, uint32_t& s1, uint32_t& s2, uint32_t& s3) {
			s0 = (s0 & ~(0xFFu << (8 * r))) | ((row & 0xFF) << (8 * r));
			s1 = (s1 & ~(0xFFu << (8 * r))) | (((row >> 8) & 0xFF) << (8 * r));
			s2 = (s2 & ~(0xFFu << (8 * r))) | (((row >> 16) & 0xFF) << (8 * r));
			s3 = (s3 & ~(0xFFu << (8 * r))) | (((row >> 24) & 0xFF) << (8 * r));
		}


		inline void replaceByteInWord(uint32_t& word, uint8_t newByte, uint8_t byteIndex) {
			word = (word & ~(0xFFu << (8 * byteIndex))) | (uint32_t)newByte << (8 * byteIndex);
		}
		inline uint8_t getByteFromWord(uint32_t word, uint8_t byteIndex) {
			return (word >> 8 * byteIndex) & 0xFF;
		}

		inline uint32_t subWord(uint32_t word) {
			return (uint32_t)con::sbox[word & 0xFF] | (uint32_t)con::sbox[(word >> 8) & 0xFF] << 8 | (uint32_t)con::sbox[(word >> 16) & 0xFF] << 16| (uint32_t)con::sbox[(word >> 24) & 0xFF] << 24;
		}

		inline uint32_t inverseSubWord(uint32_t word) {
			return (uint32_t)con::inverse_sbox[word & 0xFF] | (uint32_t)con::inverse_sbox[(word >> 8) & 0xFF] << 8 | (uint32_t)con::inverse_sbox[(word >> 16) & 0xFF] << 16 | (uint32_t)con::inverse_sbox[(word >> 24) & 0xFF] << 24;
		}

		void printBlock(AESBlock block);

		std::array<uint8_t, 256> computeSBox();
		std::array<uint8_t, 256> computeInverseSBox();

	}
};