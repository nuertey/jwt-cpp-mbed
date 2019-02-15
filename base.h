#pragma once

#include <string>
#include <array>
#include <type_traits>
#include <system_error>
#include <cstdlib>

#include "mbedtls/error.h"
#include "mbed-trace/mbed_trace.h"

enum class ErrorStatus_t : int
{
    SUCCESS                                    =     0,
    GENERIC_ERROR                              =    -1,
    MEMORY_ALLOCATION_ERROR                    =   -10,
    BUFFER_SIZE_INSUFFICIENT_ERROR             =   -11,
    PARSE_KEY_ERROR                            =   -12,
    INCORRECT_KEY_TYPE_ERROR                   =   -13,
    SIGNATURE_VERIFICATION_ERROR               =   -20,
    SIGNATURE_GENERATION_ERROR                 =   -21,
    RSA_HASH_CALCULATION_ERROR                 =   -22,
    ECDSA_HASH_CALCULATION_ERROR               =   -23,
    TOKEN_VERIFICATION_ERROR                   =   -24,
    INTERNAL_LOGIC_ERROR                       =   -30,
    BAD_CAST_STRING_ERROR                      =   -31,
    BAD_CAST_INT_ERROR                         =   -32,
    BAD_CAST_ARRAY_ERROR                       =   -33,
    BAD_CAST_SET_ERROR                         =   -34,
    BAD_CAST_BOOL_ERROR                        =   -35,
    BAD_CAST_NUMBER_ERROR                      =   -36,
    INVALID_TOKEN_ARGUMENT_ERROR               =   -37,
    INVALID_JSON_DETECTED_ERROR                =   -38,
    CLAIM_NOT_FOUND_ERROR                      =   -39,
    ENTROPY_SOURCE_FAILED                      =   -40,
    INVALID_INPUT_RUNTIME_ERROR                =   -41,
};

namespace std
{
    template <>
    struct is_error_code_enum<ErrorStatus_t> : std::true_type {};
}

struct JWTErrorCategory : std::error_category
{
    const char* name() const noexcept override;
    std::string message(int ev) const override;
};

inline const char* JWTErrorCategory::name() const noexcept
{
    return "JWT-Mbed";
}

inline std::string JWTErrorCategory::message(int ev) const
{
    switch (static_cast<ErrorStatus_t>(ev))
    {
        case ErrorStatus_t::SUCCESS:
            return "Success. No errors";

        case ErrorStatus_t::GENERIC_ERROR:
            return "Generic failure occurred";

        case ErrorStatus_t::MEMORY_ALLOCATION_ERROR:
            return "Memory allocation failed";

        case ErrorStatus_t::BUFFER_SIZE_INSUFFICIENT_ERROR:
            return "Buffer size too small";

        case ErrorStatus_t::PARSE_KEY_ERROR:
            return "Parsing private or public key failed";

        case ErrorStatus_t::INCORRECT_KEY_TYPE_ERROR:
            return "Incorrect private key type detected";

        case ErrorStatus_t::SIGNATURE_VERIFICATION_ERROR:
            return "signature verification failed";

        case ErrorStatus_t::SIGNATURE_GENERATION_ERROR:
            return "signature generation failed";
            
        case ErrorStatus_t::RSA_HASH_CALCULATION_ERROR:
            return "RSA message digest (i.e. hash) calculation error";

        case ErrorStatus_t::ECDSA_HASH_CALCULATION_ERROR:
            return "ECDSA message digest (i.e. hash) calculation error";

        case ErrorStatus_t::TOKEN_VERIFICATION_ERROR:
            return "token verification failed";
        
        case ErrorStatus_t::INTERNAL_LOGIC_ERROR:
            return "internal logic failed";

        case ErrorStatus_t::BAD_CAST_STRING_ERROR:
            return "Content was not a string. Cast failed";
        
        case ErrorStatus_t::BAD_CAST_INT_ERROR:
            return "Content was not an int. Cast failed";
        
        case ErrorStatus_t::BAD_CAST_ARRAY_ERROR:
            return "Content was not an array. Cast failed";

        case ErrorStatus_t::BAD_CAST_SET_ERROR:
            return "Content was not a set. Cast failed";

        case ErrorStatus_t::BAD_CAST_BOOL_ERROR:
            return "Content was not a boolean. Cast failed";

        case ErrorStatus_t::BAD_CAST_NUMBER_ERROR:
            return "Content was not a number. Cast failed";
        
        case ErrorStatus_t::INVALID_TOKEN_ARGUMENT_ERROR:
            return "Invalid token argument supplied";
            
        case ErrorStatus_t::INVALID_JSON_DETECTED_ERROR:
            return "Invalid JSON detected error";
            
        case ErrorStatus_t::CLAIM_NOT_FOUND_ERROR:
            return "Runtime error. Claim not found error";
            
        case ErrorStatus_t::ENTROPY_SOURCE_FAILED:
            return "Failed in mbed_tls_ctr_drbg_seed()";
            
        case ErrorStatus_t::INVALID_INPUT_RUNTIME_ERROR:
            return "Runtime error. Invalid input";                                                                
        default:
            return "(unrecognized error)";
    }
}

template <typename E>
inline constexpr auto ToIntegral(E e) -> typename std::underlying_type<E>::type
{
    return static_cast<typename std::underlying_type<E>::type>(e);
}
    
const JWTErrorCategory theJWTErrorCategory {};

inline std::error_code make_error_code(ErrorStatus_t e)
{
    return {ToIntegral(e), theJWTErrorCategory};
}

namespace jwt
{
    namespace alphabet
    {
        struct base64
        {
            static const std::array<char, 64>& data()
            {
                static std::array<char, 64> data =
                {
                    {
                        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
                    }
                };
                return data;
            };
            static const std::string& fill()
            {
                static std::string fill = "=";
                return fill;
            }
        };
        struct base64url
        {
            static const std::array<char, 64>& data()
            {
                static std::array<char, 64> data =
                {
                    {
                        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
                    }
                };
                return data;
            };
            static const std::string& fill()
            {
                static std::string fill = "%3d";
                return fill;
            }
        };
    }

    class base
    {
    public:
        template<typename T>
        static std::string encode(const std::string& bin)
        {
            return encode(bin, T::data(), T::fill());
        }
        template<typename T>
        static std::string decode(const std::string& base, std::error_code& ec)
        {
            return decode(base, T::data(), T::fill(), ec);
        }

    private:
        static std::string encode(const std::string& bin, const std::array<char, 64>& alphabet, const std::string& fill)
        {
            size_t size = bin.size();
            std::string res;

            // clear incomplete bytes
            size_t fast_size = size - size % 3;
            for (size_t i = 0; i < fast_size;)
            {
                uint32_t octet_a = (unsigned char)bin[i++];
                uint32_t octet_b = (unsigned char)bin[i++];
                uint32_t octet_c = (unsigned char)bin[i++];

                uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

                res += alphabet[(triple >> 3 * 6) & 0x3F];
                res += alphabet[(triple >> 2 * 6) & 0x3F];
                res += alphabet[(triple >> 1 * 6) & 0x3F];
                res += alphabet[(triple >> 0 * 6) & 0x3F];
            }

            if (fast_size == size)
                return res;

            size_t mod = size % 3;

            uint32_t octet_a = fast_size < size ? (unsigned char)bin[fast_size++] : 0;
            uint32_t octet_b = fast_size < size ? (unsigned char)bin[fast_size++] : 0;
            uint32_t octet_c = fast_size < size ? (unsigned char)bin[fast_size++] : 0;

            uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

            switch (mod)
            {
            case 1:
                res += alphabet[(triple >> 3 * 6) & 0x3F];
                res += alphabet[(triple >> 2 * 6) & 0x3F];
                res += fill;
                res += fill;
                break;
            case 2:
                res += alphabet[(triple >> 3 * 6) & 0x3F];
                res += alphabet[(triple >> 2 * 6) & 0x3F];
                res += alphabet[(triple >> 1 * 6) & 0x3F];
                res += fill;
                break;
            default:
                break;
            }

            return res;
        }

        static std::string decode(const std::string& base, 
                                  const std::array<char, 64>& alphabet, 
                                  const std::string& fill,
                                  std::error_code& ec)
        {
            size_t size = base.size();

            size_t fill_cnt = 0;
            while (size > fill.size())
            {
                if (base.substr(size - fill.size(), fill.size()) == fill)
                {
                    fill_cnt++;
                    size -= fill.size();
                    if (fill_cnt > 2)
                    {
                        tr_error("Invalid input");
                        ec = make_error_code(ErrorStatus_t::INVALID_INPUT_RUNTIME_ERROR);
                        return "";
                    }
                }
                else break;
            }

            if ((size + fill_cnt) % 4 != 0)
            {
                tr_error("Invalid input");
                ec = make_error_code(ErrorStatus_t::INVALID_INPUT_RUNTIME_ERROR);
                return "";
            }

            size_t out_size = size / 4 * 3;
            std::string res;
            res.reserve(out_size);

            auto get_sextet = [&](size_t offset, std::error_code& ec)
            {
                for (size_t i = 0; i < alphabet.size(); i++)
                {
                    if (alphabet[i] == base[offset])
                        return i;
                }
                tr_error("Invalid input");
                ec = make_error_code(ErrorStatus_t::INVALID_INPUT_RUNTIME_ERROR);
                return (size_t)0;
            };

            size_t fast_size = size - size % 4;
            for (size_t i = 0; i < fast_size;)
            {
                uint32_t sextet_a = get_sextet(i++, ec);
                uint32_t sextet_b = get_sextet(i++, ec);
                uint32_t sextet_c = get_sextet(i++, ec);
                uint32_t sextet_d = get_sextet(i++, ec);

                uint32_t triple = (sextet_a << 3 * 6)
                                  + (sextet_b << 2 * 6)
                                  + (sextet_c << 1 * 6)
                                  + (sextet_d << 0 * 6);

                res += (triple >> 2 * 8) & 0xFF;
                res += (triple >> 1 * 8) & 0xFF;
                res += (triple >> 0 * 8) & 0xFF;
            }

            if (fill_cnt == 0)
                return res;

            uint32_t triple = (get_sextet(fast_size, ec) << 3 * 6)
                              + (get_sextet((fast_size + 1), ec) << 2 * 6);

            switch (fill_cnt)
            {
            case 1:
                triple |= (get_sextet((fast_size + 2), ec) << 1 * 6);
                res += (triple >> 2 * 8) & 0xFF;
                res += (triple >> 1 * 8) & 0xFF;
                break;
            case 2:
                res += (triple >> 2 * 8) & 0xFF;
                break;
            default:
                break;
            }

            return res;
        }
    };
}
