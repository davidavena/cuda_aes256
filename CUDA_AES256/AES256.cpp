#include "AES256.hpp"

namespace aes {

    void generateRoundKeys(AES256Context& context, std::array<uint8_t, 32> bytes) {
        std::array<uint32_t, 60> expanded = key_sched::expandWords(bytes);
        for (size_t i = 0; i < 15; i++) {
            context.roundkeys[i].word[0] = expanded[i * 4];
            context.roundkeys[i].word[1] = expanded[i * 4 + 1];
            context.roundkeys[i].word[2] = expanded[i * 4 + 2];
            context.roundkeys[i].word[3] = expanded[i * 4 + 3];
        }
        context.roundKeysSet = true;
    }

    void generateRoundKeys(AES256Context& context, const std::string& hexString) {
        std::vector<uint8_t> bytes = util::parseHexString(hexString);
        std::array<uint8_t, 32> byteArray;
        std::copy(bytes.begin(), bytes.end(), byteArray.begin());
        key_sched::expandWords(byteArray);
        generateRoundKeys(context, byteArray);
    }

    

   

    namespace ecb {
        std::vector<uint8_t> encrypt(AES256Context& context, std::vector<uint8_t>& raw_data) {
            util::applyPKCS7padding(raw_data);
            std::vector<AESBlock> blocks = util::convertToAESBlocks(raw_data);

            for (AESBlock& block : blocks) {
                transform::addRoundKey(block, context.roundkeys[0]);
            }

            for (size_t i = 1; i < 14; i++) {
                for (AESBlock& block : blocks) {
                    transform::subBytes(block);
                    transform::shiftRows(block);
                    transform::mixColumns(block);
                    transform::addRoundKey(block, context.roundkeys[i]);
                }
            }

            for (AESBlock& block : blocks) {
                transform::subBytes(block);
                transform::shiftRows(block);
                transform::addRoundKey(block, context.roundkeys[14]);
            }

            std::vector<uint8_t> newData = util::convertToRawData(blocks);
            return newData;
        }

        std::vector<uint8_t> decrypt(AES256Context& context, std::vector<uint8_t>& raw_data) {
            std::vector<AESBlock> blocks = util::convertToAESBlocks(raw_data);

            for (AESBlock& block : blocks) {
                transform::addRoundKey(block, context.roundkeys[14]);
            }

            for (int i = 13; i > 0; i--) {
                for (AESBlock& block : blocks) {
                    transform::inverseShiftRows(block);
                    transform::inverseSubBytes(block);
                    transform::addRoundKey(block, context.roundkeys[i]);
                    transform::inverseMixColumns(block);
                }
            }

            for (AESBlock& block : blocks) {
                transform::inverseShiftRows(block);
                transform::inverseSubBytes(block);
                transform::addRoundKey(block, context.roundkeys[0]);
            }

            std::vector<uint8_t> newData = util::convertToRawData(blocks);
            util::removePKCS7padding(newData);
            return newData;
        }
    }

    namespace key_sched {
        std::array<uint32_t, 60> expandWords(std::array<uint8_t, 32> keyBytes) {
            std::array<uint32_t, 60> output;
            std::array<uint32_t, 8> initialWords;
            for (size_t i = 0; i < 8; i++) {
                initialWords[i] = keyBytes[4 * i] << 24 | keyBytes[4 * i + 1] << 16 | keyBytes[4 * i + 2] << 8 | keyBytes[4 * i + 3];
            }
            memmove(output.data(), initialWords.data(), 8 * sizeof(uint32_t));

            for (size_t i = 8; i < 60; i++) {
                uint8_t remainder = i % 8;
                switch (remainder) {
                case 0:
                    output[i] = output[i - 8] ^ util::subWord(rotWord(output[i - 1])) ^ (rcon(i / 8));
                    break;
                case 4:
                    output[i] = output[i - 8] ^ util::subWord(output[i - 1]);
                    break;
                default:
                    output[i] = output[i - 8] ^ output[i - 1];
                    break;
                }
            }
            return output;
        }
    }

    namespace transform {
        void addRoundKey(AESBlock& block, RoundKey roundKey) {
            for (size_t col = 0; col < 4; col++) {
                uint32_t s = block.state[col];
                util::replaceByteInWord(s, util::getByteFromWord(s,0) ^ util::getByteFromWord(roundKey.word[col], 3), 0);
                util::replaceByteInWord(s, util::getByteFromWord(s, 1) ^ util::getByteFromWord(roundKey.word[col], 2), 1);
                util::replaceByteInWord(s, util::getByteFromWord(s, 2) ^ util::getByteFromWord(roundKey.word[col], 1), 2);
                util::replaceByteInWord(s, util::getByteFromWord(s, 3) ^ util::getByteFromWord(roundKey.word[col], 0), 3);
                block.state[col] = s;
            }
        }
        void subBytes(AESBlock& block) {
            for (size_t col = 0; col < 4; col++) {
                uint32_t s = block.state[col];
                util::replaceByteInWord(s, con::sbox[util::getByteFromWord(s, 0)], 0);
                util::replaceByteInWord(s, con::sbox[util::getByteFromWord(s, 1)], 1);
                util::replaceByteInWord(s, con::sbox[util::getByteFromWord(s, 2)], 2);
                util::replaceByteInWord(s, con::sbox[util::getByteFromWord(s, 3)], 3);
                block.state[col] = s;
            }
        }
        void shiftRows(AESBlock& block) {
            uint32_t r1 = util::extractRow(block.state[0], block.state[1], block.state[2], block.state[3], 1);
            uint32_t r2 = util::extractRow(block.state[0], block.state[1], block.state[2], block.state[3], 2);
            uint32_t r3 = util::extractRow(block.state[0], block.state[1], block.state[2], block.state[3], 3);

            r1 = (r1 >> 8) | (r1 << 24);
            r2 = (r2 >> 16) | (r2 << 16);
            r3 = (r3 << 8) | (r3 >> 24);

            util::rowScatter(r1, 1, block.state[0], block.state[1], block.state[2], block.state[3]);
            util::rowScatter(r2, 2, block.state[0], block.state[1], block.state[2], block.state[3]);
            util::rowScatter(r3, 3, block.state[0], block.state[1], block.state[2], block.state[3]);
        }
        void mixColumns(AESBlock& block) {
            for (size_t col = 0; col < 4; col++) {
                uint32_t state = block.state[col];
                uint8_t b0 = util::getByteFromWord(state, 0);
                uint8_t b1 = util::getByteFromWord(state, 1);
                uint8_t b2 = util::getByteFromWord(state, 2);
                uint8_t b3 = util::getByteFromWord(state, 3);

                uint8_t b0p = con::mixColumnLookup[util::Hex02][b0] ^ con::mixColumnLookup[util::Hex03][b1] ^ con::mixColumnLookup[util::Hex01][b2] ^ con::mixColumnLookup[util::Hex01][b3];
                uint8_t b1p = con::mixColumnLookup[util::Hex01][b0] ^ con::mixColumnLookup[util::Hex02][b1] ^ con::mixColumnLookup[util::Hex03][b2] ^ con::mixColumnLookup[util::Hex01][b3];
                uint8_t b2p = con::mixColumnLookup[util::Hex01][b0] ^ con::mixColumnLookup[util::Hex01][b1] ^ con::mixColumnLookup[util::Hex02][b2] ^ con::mixColumnLookup[util::Hex03][b3];
                uint8_t b3p = con::mixColumnLookup[util::Hex03][b0] ^ con::mixColumnLookup[util::Hex01][b1] ^ con::mixColumnLookup[util::Hex01][b2] ^ con::mixColumnLookup[util::Hex02][b3];

                block.state[col] = (b0p) | (b1p << 8) | (b2p << 16) | (b3p << 24);
            }
        }

        void inverseSubBytes(AESBlock& block) {
            for (size_t col = 0; col < 4; col++) {
                uint32_t s = block.state[col];
                util::replaceByteInWord(s, con::inverse_sbox[util::getByteFromWord(s, 0)], 0);
                util::replaceByteInWord(s, con::inverse_sbox[util::getByteFromWord(s, 1)], 1);
                util::replaceByteInWord(s, con::inverse_sbox[util::getByteFromWord(s, 2)], 2);
                util::replaceByteInWord(s, con::inverse_sbox[util::getByteFromWord(s, 3)], 3);
                block.state[col] = s;
            }
        }
        void inverseShiftRows(AESBlock& block) {
            uint32_t r1 = util::extractRow(block.state[0], block.state[1], block.state[2], block.state[3], 1);
            uint32_t r2 = util::extractRow(block.state[0], block.state[1], block.state[2], block.state[3], 2);
            uint32_t r3 = util::extractRow(block.state[0], block.state[1], block.state[2], block.state[3], 3);

            r1 = (r1 << 8) | (r1 >> 24);
            r2 = (r2 << 16) | (r2 >> 16);
            r3 = (r3 >> 8) | (r3 << 24);

            util::rowScatter(r1, 1, block.state[0], block.state[1], block.state[2], block.state[3]);
            util::rowScatter(r2, 2, block.state[0], block.state[1], block.state[2], block.state[3]);
            util::rowScatter(r3, 3, block.state[0], block.state[1], block.state[2], block.state[3]);
        }
        void inverseMixColumns(AESBlock& block) {
            for (size_t col = 0; col < 4; col++) {
                uint32_t state = block.state[col];
                uint8_t b0 = util::getByteFromWord(state, 0);
                uint8_t b1 = util::getByteFromWord(state, 1);
                uint8_t b2 = util::getByteFromWord(state, 2);
                uint8_t b3 = util::getByteFromWord(state, 3);

                uint8_t b0p = con::invMixColumnLookup[util::Hex0e][b0] ^ con::invMixColumnLookup[util::Hex0b][b1] ^ con::invMixColumnLookup[util::Hex0d][b2] ^ con::invMixColumnLookup[util::Hex09][b3];
                uint8_t b1p = con::invMixColumnLookup[util::Hex09][b0] ^ con::invMixColumnLookup[util::Hex0e][b1] ^ con::invMixColumnLookup[util::Hex0b][b2] ^ con::invMixColumnLookup[util::Hex0d][b3];
                uint8_t b2p = con::invMixColumnLookup[util::Hex0d][b0] ^ con::invMixColumnLookup[util::Hex09][b1] ^ con::invMixColumnLookup[util::Hex0e][b2] ^ con::invMixColumnLookup[util::Hex0b][b3];
                uint8_t b3p = con::invMixColumnLookup[util::Hex0b][b0] ^ con::invMixColumnLookup[util::Hex0d][b1] ^ con::invMixColumnLookup[util::Hex09][b2] ^ con::invMixColumnLookup[util::Hex0e][b3];

                block.state[col] = (b0p) | (b1p << 8) | (b2p << 16) | (b3p << 24);
            }
        }
    }

	namespace util {
        void applyPKCS7padding(std::vector<uint8_t>& data) {
            uint8_t padValue = 16 - (data.size() % 16);
            for (uint8_t i = 0; i < padValue; i++) {
                data.push_back(padValue);
            }
        }

        void removePKCS7padding(std::vector<uint8_t>& data) {
            uint8_t remove = data[data.size() - 1];
            for (uint8_t i = 0; i < remove; i++) {
                data.pop_back();
            }
        }

        std::vector<uint8_t> convertToRawData(std::vector<AESBlock>& blocks) {
            std::vector<uint8_t> data;
            for (AESBlock block : blocks) {
                for (size_t stateIndex = 0; stateIndex < 4; stateIndex++) {
                    uint32_t word = block.state[stateIndex];
                    for (size_t byteIndex = 0; byteIndex < 4; byteIndex++) {
                        char c = static_cast<char>(getByteFromWord(word, byteIndex));
                        data.push_back(c);
                    }
                }
            }
            return data;
        }

        std::vector<AESBlock> convertToAESBlocks(const std::vector<uint8_t>& data) {
            size_t numberOfBlocks = (data.size() + 15) / 16;
            std::vector<AESBlock> blocks;
            for (size_t i = 0; i < numberOfBlocks; i++) {
                AESBlock block;
                uint32_t w0 = combineBytesIntoWord(data[16 * i], data[16 * i + 1], data[16 * i + 2], data[16 * i + 3]);
                uint32_t w1 = combineBytesIntoWord(data[16 * i + 4], data[16 * i + 5], data[16 * i + 6], data[16 * i + 7]);
                uint32_t w2 = combineBytesIntoWord(data[16 * i + 8], data[16 * i + 9], data[16 * i + 10], data[16 * i + 11]);
                uint32_t w3 = combineBytesIntoWord(data[16 * i + 12], data[16 * i + 13], data[16 * i + 14], data[16 * i + 15]);
                block.state[0] = w0;
                block.state[1] = w1;
                block.state[2] = w2;
                block.state[3] = w3;
                blocks.push_back(block);
            }
            return blocks;
        }

        std::vector<uint8_t> parseHexString(const std::string& hexString) {
            if (hexString.length() % 2 != 0) throw std::invalid_argument("Input String in function 'parseHexString' has an odd length.");

            std::vector<uint8_t> output(hexString.length() / 2);
            for (size_t i = 0; i < output.size(); i++) {
                uint32_t value = 0;
                const auto ret = std::from_chars(hexString.data() + (2 * i), hexString.data() + (2 * i) + 2, value, 16);

                if (ret.ec != std::errc{}) throw std::invalid_argument("Input String in function 'parseHexString' has an invalid character.");
                output[i] = static_cast<uint8_t>(value);
            }
            return output;
        }

        uint8_t galoisMulti(uint8_t b1, uint8_t b2) {
            uint8_t product = 0;
            while (b2) {
                if (b2 & 1) product ^= b1;
                bool overflow = b1 & 0x80;
                b1 <<= 1;
                if (overflow) b1 ^= 0x1B;
                b2 >>= 1;
            }
            return product;
        }

        uint8_t galoisInverseBrute(uint8_t byte) {
            if (byte == 0) return 0;
            for (size_t i = 1; i < 256; i++) {
                if (galoisMulti(byte, static_cast<uint8_t>(i)) == 1) return static_cast<uint8_t>(i);
            }
            return 0;
        }

        uint8_t affineTransform(uint8_t x) {
            uint8_t y = 0;
            uint8_t c = 0x63;
            for (int i = 0; i < 8; i++) {
                uint8_t bit = ((x >> i) & 1) ^
                    ((x >> ((i + 4) % 8)) & 1) ^
                    ((x >> ((i + 5) % 8)) & 1) ^
                    ((x >> ((i + 6) % 8)) & 1) ^
                    ((x >> ((i + 7) % 8)) & 1) ^
                    ((c >> i) & 1);
                y |= (bit << i);
            }
            return y;
        }

        void printBlock(AESBlock block) {
            std::array<uint8_t, 16> data;
            for (size_t col = 0; col < 4; col++) {
                std::cout << "Col " << col + 1 << ": ";
                for (size_t row = 0; row < 4; row++) {
                    std::cout << std::hex << (size_t)getByteFromWord(block.state[col], row) << ' ';
                }
                std::cout << '\n';
            }
        }

        uint8_t substituteByteInSBox(uint8_t byte) {
            return affineTransform(galoisInverseBrute(byte));
        }

		std::array<uint8_t, 256> computeSBox() {
            std::array<uint8_t, 256> arr;
            for (size_t i = 0; i < 256; i++) {
                arr[i] = substituteByteInSBox(static_cast<uint8_t>(i));
            }
            return arr;
		}

        std::array<uint8_t, 256> computeInverseSBox() {
            std::array<uint8_t, 256> arr;
            for (size_t i = 0; i < 256; i++) {
                uint8_t substitutedByte = substituteByteInSBox(static_cast<uint8_t>(i));
                arr[substitutedByte] = static_cast<uint8_t>(i);
            }
            return arr;
        }

	}
}