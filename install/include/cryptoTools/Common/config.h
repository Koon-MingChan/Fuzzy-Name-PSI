#pragma once


// use the miracl library for curves
/* #undef ENABLE_MIRACL */

// use the relic library for curves
/* #undef ENABLE_RELIC */

// use the libsodium library for curves
/* #undef ENABLE_SODIUM */

// does the libsodium library support noclamp operations on Montgomery curves?
/* #undef SODIUM_MONTGOMERY */

// compile the circuit library
/* #undef ENABLE_CIRCUITS */

// include the span-lite
/* #undef ENABLE_SPAN_LITE */

// defined if we should use cpp 14 and undefined means cpp 11
/* #undef ENABLE_CPP_14 */

// Turn on Channel logging for debugging.
/* #undef ENABLE_NET_LOG */


// enable the wolf ssl socket layer.
/* #undef ENABLE_WOLFSSL */

// enable integration with boost for networking.
/* #undef ENABLE_BOOST */

// enable the use of ARM AES instructions.
/* #undef ENABLE_ARM_AES */

// enable the use of intel SSE instructions.
#define ENABLE_SSE ON

// enable the use of intel AVX instructions.
#define ENABLE_AVX ON

// enable the use of intel AVX2 instructions.
#define ENABLE_AVX2 ON

// enable the use of intel AVX512 instructions.
#define ENABLE_AVX512 ON

// enable the use of intel BMI2 instructions.
#define ENABLE_BMI2 ON



// enable the use of the portable AES implementation.
/* #undef ENABLE_PORTABLE_AES */

#if (defined(_MSC_VER) || defined(__SSE2__)) && defined(ENABLE_SSE)
#define ENABLE_SSE_BLAKE2 ON
#define OC_ENABLE_SSE2 ON
#endif

#if (defined(_MSC_VER) || defined(__PCLMUL__)) && defined(ENABLE_SSE)
#define OC_ENABLE_PCLMUL
#endif

#if (defined(_MSC_VER) || defined(__AES__)) && defined(ENABLE_SSE)
#define OC_ENABLE_AESNI ON
#endif

#if defined(ENABLE_PORTABLE_AES)
	#define OC_ENABLE_PORTABLE_AES ON
#endif

#if (defined(_MSC_VER) || defined(__AVX2__)) && defined(ENABLE_AVX)
#define OC_ENABLE_AVX2 ON
#endif





#ifdef __CUDACC__
    #define OC_CUDA_CALLABLE __host__ __device__
    #define OC_CUDA_DEVICE __device__
    #define OC_CUDA_HOST __host__ 
    
    #ifdef OC_ENABLE_PCLMUL
        #undef OC_ENABLE_PCLMUL
    #endif
    #ifdef OC_ENABLE_SSE2
        #undef OC_ENABLE_SSE2
    #endif
    
    #ifdef ENABLE_SSE
        #undef ENABLE_SSE
    #endif
    #ifdef OC_ENABLE_SSE
        #undef OC_ENABLE_SSE
    #endif
    #ifdef ENABLE_AVX
        #undef ENABLE_AVX
    #endif
    #ifdef ENABLE_ARM_AES
        #undef ENABLE_ARM_AES
    #endif
    #if !defined(ENABLE_PORTABLE_AES)
        #define ENABLE_PORTABLE_AES 
    #endif
#else
    #define OC_CUDA_CALLABLE
    #define OC_CUDA_DEVICE
    #define OC_CUDA_HOST

#endif
