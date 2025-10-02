

#include "CUDA_AES256.cuh"
#include "FileReader.hpp"
#include <stdio.h>

cudaError_t addWithCuda(int *c, const int *a, const int *b, unsigned int size);

__global__ void addKernel(int *c, const int *a, const int *b)
{
    int i = threadIdx.x;
    c[i] = a[i] + b[i];
}

int main()
{
    std::ifstream inputFile;
    file::openFile(inputFile, "input.txt");
    std::streamsize fileSize = file::getFileSize(inputFile);
    std::vector<char> rawFileData(fileSize);
    file::extractBytes(inputFile, rawFileData, fileSize);
    file::closeFile(inputFile);

    //aes::util::computeSBox();
    //aes::util::computeInverseSBox();

    aes::AES256Context context;

    std::string key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    std::vector<uint8_t> bytes = aes::util::parseHexString(key);
    std::array<uint8_t, 32> b;
    std::copy(bytes.begin(), bytes.end(), b.begin());
    std::array<uint32_t, 60> expand = aes::key_sched::expandWords(b);
    for (uint32_t key : expand) {
        //std::cout << key << '\n';
    }
    aes::generateRoundKeys(context, b);
    aes::AESBlock block;
    aes::transform::addRoundKey(block, context.roundkeys[0]);
    aes::transform::shiftRows(block);
    aes::util::printBlock(block);
    aes::transform::mixColumns(block);
    aes::util::printBlock(block);
    aes::transform::inverseMixColumns(block);
    aes::util::printBlock(block);

    uint32_t byte = 0x1a2b3c4d;
    byte = aes::util::subWord(byte);
    //std::cout << std::hex << (size_t)aes::util::getByteFromWord(byte, 1) << '\n';
    //std::cout << (size_t)aes::sbox[0x3c];
    uint8_t newByte = 255;

    return 0;
}

// Helper function for using CUDA to add vectors in parallel.
cudaError_t addWithCuda(int *c, const int *a, const int *b, unsigned int size)
{
    int *dev_a = 0;
    int *dev_b = 0;
    int *dev_c = 0;
    cudaError_t cudaStatus;

    // Choose which GPU to run on, change this on a multi-GPU system.
    cudaStatus = cudaSetDevice(0);
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaSetDevice failed!  Do you have a CUDA-capable GPU installed?");
        goto Error;
    }

    // Allocate GPU buffers for three vectors (two input, one output)    .
    cudaStatus = cudaMalloc((void**)&dev_c, size * sizeof(int));
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMalloc failed!");
        goto Error;
    }

    cudaStatus = cudaMalloc((void**)&dev_a, size * sizeof(int));
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMalloc failed!");
        goto Error;
    }

    cudaStatus = cudaMalloc((void**)&dev_b, size * sizeof(int));
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMalloc failed!");
        goto Error;
    }

    // Copy input vectors from host memory to GPU buffers.
    cudaStatus = cudaMemcpy(dev_a, a, size * sizeof(int), cudaMemcpyHostToDevice);
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMemcpy failed!");
        goto Error;
    }

    cudaStatus = cudaMemcpy(dev_b, b, size * sizeof(int), cudaMemcpyHostToDevice);
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMemcpy failed!");
        goto Error;
    }

    // Launch a kernel on the GPU with one thread for each element.
    addKernel<<<1, size>>>(dev_c, dev_a, dev_b);

    // Check for any errors launching the kernel
    cudaStatus = cudaGetLastError();
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "addKernel launch failed: %s\n", cudaGetErrorString(cudaStatus));
        goto Error;
    }
    
    // cudaDeviceSynchronize waits for the kernel to finish, and returns
    // any errors encountered during the launch.
    cudaStatus = cudaDeviceSynchronize();
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaDeviceSynchronize returned error code %d after launching addKernel!\n", cudaStatus);
        goto Error;
    }

    // Copy output vector from GPU buffer to host memory.
    cudaStatus = cudaMemcpy(c, dev_c, size * sizeof(int), cudaMemcpyDeviceToHost);
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMemcpy failed!");
        goto Error;
    }

Error:
    cudaFree(dev_c);
    cudaFree(dev_a);
    cudaFree(dev_b);
    
    return cudaStatus;
}
