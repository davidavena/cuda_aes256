#include "AESConstants.hpp"

#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <iostream>
#include <array>
#include <vector>
#include <charconv>

namespace cuda_aes {
    cudaError_t cuda_init(int device);


}