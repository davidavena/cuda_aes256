#include "CUDA_AES256.cuh"

namespace cuda_aes {
    cudaError_t cuda_init(int device) {
        cudaError_t cudaStatus;

        cudaStatus = cudaSetDevice(device);
        if (cudaStatus != cudaSuccess) throw std::runtime_error("Runtime Error | cuda_init(): Error while setting device");

        cudaStatus = cudaMemcpyToSymbol(aes::cuda_con::sbox, aes::con::sbox, sizeof(aes::con::sbox));
        if (cudaStatus != cudaSuccess) throw std::runtime_error("Runtime Error | cuda_init(): Error copying sbox");

        cudaStatus = cudaMemcpyToSymbol(aes::cuda_con::inverse_sbox, aes::con::inverse_sbox, sizeof(aes::con::inverse_sbox));
        if (cudaStatus != cudaSuccess) throw std::runtime_error("Runtime Error | cuda_init(): Error copying inverse_sbox");

        cudaStatus = cudaMemcpyToSymbol(aes::cuda_con::mixColumnLookup, aes::con::mixColumnLookup, sizeof(aes::con::mixColumnLookup));
        if (cudaStatus != cudaSuccess) throw std::runtime_error("Runtime Error | cuda_init(): Error copying mixColumnLookup");

        cudaStatus = cudaMemcpyToSymbol(aes::cuda_con::invMixColumnLookup, aes::con::invMixColumnLookup, sizeof(aes::con::invMixColumnLookup));
        if (cudaStatus != cudaSuccess) throw std::runtime_error("Runtime Error | cuda_init(): Error copying invMixColumnLookup");
    }
}