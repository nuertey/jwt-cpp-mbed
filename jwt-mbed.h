/***********************************************************************
* @file
*
* Header-only library for creating and validating JSON Web Tokens. The
* library is written in C++ but geared towards ARM Mbed-enabled targets.
*
* @note     The structure and organization of the library is mostly
*           ported from jwt-cpp :
*
*           Reference : https://github.com/Thalhammer/jwt-cpp
*
* @warning  As we are on Embedded, constrained by resources, and are 
*           enforcing the prohibition of exception handling with the
*           GCC compiler flag "-fno-exceptions", we will convert all 
*           exception handling in the ported from code to std::error_code.
* 
*           This may impact the program flow and should be analyzed and
*           considered accordingly.
*
*  Created: January 30, 2019
*   Author: Nuertey Odzeyem
************************************************************************/
#pragma once

#define PICOJSON_USE_INT64
#define TRACE_GROUP "jwt"

#include "picojson.h"
#include "base.h"
#include <set>
#include <chrono>
#include <unordered_map>
#include <memory>
#include <sstream>
#include <string>
#include "mbed.h"
//#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbed-trace/mbed_trace.h"

#ifndef JWT_CLAIM_EXPLICIT
#define JWT_CLAIM_EXPLICIT 0
#endif

namespace jwt
{
    using date = std::chrono::system_clock::time_point;

    namespace algorithm
    {
        /**
         * "none" algorithm.
         *
         * Returns and empty signature and checks if the given signature is empty.
         */
        struct none
        {
            /// Return an empty string
            std::string sign(const std::string&) const
            {
                return "";
            }
            /// Check if the given signature is empty. JWT's with "none" algorithm should not contain a signature.
            void verify(const std::string&, const std::string& signature, std::error_code& ec) const
            {
                if (!signature.empty())
                {
                    ec = make_error_code(ErrorStatus_t::SIGNATURE_VERIFICATION_ERROR);
                }
            }
            /// Get algorithm name
            std::string name() const
            {
                return "none";
            }
        };
        /**
         * Base class for HMAC family of algorithms
         */
        struct hmacsha
        {
            /**
             * Construct new hmac algorithm
             * \param key Key to use for HMAC
             * \param md Pointer to hash function
             * \param name Name of the algorithm
             */
            hmacsha(std::string key, mbedtls_md_type_t& mdAlgorithm = MBEDTLS_MD_SHA1, 
                    const std::string& name)
                : m_secret(std::move(key))
                , m_messageDigestAlgorithm(mdAlgorithm)
                , m_algorithmName(name)
            {}
            /**
             * Sign jwt data
             * \param data The data to sign
             * \return HMAC signature for the given data
             * \throws signature_generation_exception
             */
            std::string sign(const std::string& data, std::error_code& ec) const
            {
                std::string res;
                mbedtls_md_context_t ctx;

                // Reserve and initialize memory for hash.
                mbetdtls_md_info_t *mdinfo = mbedtls_md_info_from_type(m_messageDigestAlgorithm);
                char *md = calloc(mdinfo->size, sizeof(char));
                
                // Calculate the message digest (i.e. hash) for the data.
                rc = mbedtls_md(mdinfo, data.data(), data.size(), md);
                
                if (rc != ErrorStatus_t::SUCCESS) 
                {
                    tr_error("HMAC failed to calculate hash (-0x%04x)", rc);
                    ec = make_error_code(ErrorStatus_t::SIGNATURE_GENERATION_ERROR);
                }
                else
                {
                    mbedtls_md_init(&ctx);  
                    mbedtls_md_setup(&ctx, mdinfo, 1); //use hmac
                    mbedtls_md_hmac_starts(&ctx, m_secret.data(), m_secret.size());
                    mbedtls_md_hmac_update(&ctx, (const unsigned char *)data.data(), data.size());    
                    mbedtls_md_hmac_finish(&ctx, md);
                    res = std::string(md, mdinfo->size);
                    mbedtls_md_free(&ctx);    
                }
                free(md);
                return res;
            }
            /**
             * Check if signature is valid
             * \param data The data to check signature against
             * \param signature Signature provided by the jwt
             * \throws signature_verification_exception If the provided signature does not match
             */
            void verify(const std::string& data, const std::string& signature,
                        std::error_code& ec) const
            {
                auto res = sign(data, ec);
                if (!ec)
                {
                    bool matched = true;
                    for (size_t i = 0; i < std::min<size_t>(res.size(), signature.size()); i++)
                        if (res[i] != signature[i])
                            matched = false;
                    if (res.size() != signature.size())
                        matched = false;
                    if (!matched)
                    {
                        tr_error("provided signature does not match");
                        ec = make_error_code(ErrorStatus_t::SIGNATURE_VERIFICATION_ERROR);
                    }
                }
            }
            /**
             * Returns the algorithm name provided to the constructor
             * \return Algorithmname
             */
            std::string name() const
            {
                return m_algorithmName;
            }
        private:
            const std::string         m_secret;                 /// HMAC secret
            const mbedtls_md_type_t   m_messageDigestAlgorithm; /// Hash generator 
            const std::string         m_algorithmName;          /// Algorithmname
        };
        /**
         * Base class for RSA family of algorithms
         */
        struct rsa
        {
            /**
             * Construct new rsa algorithm
             * \param public_key RSA public key in PEM format
             * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
             * \param public_key_password Password to decrypt public key pem.
             * \param privat_key_password Password to decrypt private key pem.
             * \param md Pointer to hash function
             * \param name Name of the algorithm
             */
            rsa(const std::string& public_key, const std::string& private_key, 
                const std::string& public_key_password="", const std::string& private_key_password="", 
                const mbedtls_md_type_t& mdAlgorithm = MBEDTLS_MD_SHA1, const std::string& name)
                : m_publicKey(public_key)
                , m_privateKey(private_key) 
                , m_publicKeyPassword(public_key_password.empty() ? 
                            std::nullopt : std::make_optional(public_key_password)) 
                , m_privateKeyPassword(private_key_password.empty() ?
                            std::nullopt : std::make_optional(private_key_password))
                , m_messageDigestAlgorithm(mdAlgorithm)
                , m_algorithmName(name)
            {
            }
            /**
             * Sign jwt data
             * \param data The data to sign
             * \return RSA signature for the given data
             * \throws signature_generation_exception
             */
            std::string sign(const std::string& data, std::error_code& ec) const
            {
                int rc = 0;
                size_t sig_len;
                char * buffer;

                mbedtls_pk_context pk;
                mbedtls_pk_init(&pk);
                
                // Parse key
                if (!m_privateKeyPassword)
                {
                    rc = mbedtls_pk_parse_key(&pk, m_privateKey.data(), 
                                          m_privateKey.size(), nullptr, 0);
                }
                else
                {
                    rc = mbedtls_pk_parse_key(&pk, m_privateKey.data(), 
                                          m_privateKey.size(), 
                                          (*m_privateKeyPassword).data(), 
                                          (*m_privateKeyPassword).size());                
                }
                if (rc != ErrorStatus_t::SUCCESS) 
                {
                    tr_warn("RSA failed to parse private key (-0x%04x)", ret);
                    ec = make_error_code(ErrorStatus_t::SIGNATURE_VERIFICATION_ERROR);
                }
                else
                {
                    // Set up CTR-DRBG
                    const char *pers = "mbedtls_pk_sign";
                    mbedtls_ctr_drbg_context ctr_drbg;
                    mbedtls_ctr_drbg_init(&ctr_drbg);

                    // Set up entropy
                    mbedtls_entropy_context entropy;
                    mbedtls_entropy_init(&entropy);
                    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                            (const unsigned char *)pers, strlen(pers));
                    mbedtls_entropy_free(&entropy);
                    
                    if (rc != ErrorStatus_t::SUCCESS) 
                    {
                        tr_err("Failed in mbed_tls_ctr_drbg_seed().");
                        mbedtls_ctr_drbg_free(&ctr_drbg);
                        mbedtls_pk_free(&pk);
                        ec = make_error_code(ErrorStatus_t::MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED);
                        return "";
                    }
                    
                    // Calculate hash
                    mbetdtls_md_info_t *mdinfo = mbedtls_md_info_from_type(m_messageDigestAlgorithm);
                    char *md = malloc(mdinfo->size);
                    
                    // Calculate the message digest (i.e. hash) for the data.
                    rc = mbedtls_md(mdinfo, data.data(), data.size(), md);
                    
                    if (rc != ErrorStatus_t::SUCCESS) 
                    {
                        tr_error("RSA failed to calculate hash (-0x%04x)", rc);
                        ec = make_error_code(ErrorStatus_t::SIGNATURE_GENERATION_ERROR);
                    }
                    else
                    {
                        buffer = new char[1024];
                        // Sign
                        rc = mbedtls_pk_sign(&pk, mdinfo->type, md, 
                                mdinfo->size, buffer, &sig_len, 
                                mbedtls_ctr_drbg_random, &ctr_drbg);
                    }
                    free(md);
                    mbedtls_ctr_drbg_free(&ctr_drbg);
                }
                mbedtls_pk_free(&pk);

                if (rc != ErrorStatus_t::SUCCESS) 
                {
                    tr_err("Failed in mbedtls_pk_sign.");
                    ec = make_error_code(ErrorStatus_t::SIGNATURE_GENERATION_ERROR);
                    delete []buffer;
                    return "";
                }

                std::string res(buffer, sig_len);
                delete []buffer;
                return res;
            }
            /**
             * Check if signature is valid
             * \param data The data to check signature against
             * \param signature Signature provided by the jwt
             * \throws signature_verification_exception If the provided signature does not match
             */
            void verify(const std::string& data, const std::string& signature, 
                        std::error_code& ec) const
            {
                int ret;
                mbedtls_pk_context pk;
                mbedtls_pk_init(&pk);

                ret = mbedtls_pk_parse_public_key(&pk, m_publicKey.data(), m_publicKey.size());
                if (ret != ErrorStatus_t::SUCCESS) 
                {
                    tr_warn("RSA failed to parse public key (-0x%04x)", ret);
                    ec = make_error_code(ErrorStatus_t::SIGNATURE_VERIFICATION_ERROR);
                }
                else
                {
                    mbetdtls_md_info_t *mdinfo = mbedtls_md_info_from_type(m_messageDigestAlgorithm);
                    char *md = malloc(mdinfo->size);
                    
                    // Calculate the message digest (i.e. hash) for the data.
                    ret = mbedtls_md(mdinfo, data.data(), data.size(), md);
                    
                    if (ret != ErrorStatus_t::SUCCESS) 
                    {
                        tr_error("RSA failed to verify message (-0x%04x)", ret);
                        ec = make_error_code(ErrorStatus_t::SIGNATURE_VERIFICATION_ERROR);
                    }
                    else
                    {
                        // Now verify the signature for the given hash of the data.
                        ret = mbedtls_pk_verify(&pk, 
                                                mdinfo->type, md, mdinfo->size,
                                                (const unsigned char*)signature.data(), 
                                                signature.size());

                        if (ret != ErrorStatus_t::SUCCESS) 
                        {
                            tr_error("RSA failed to verify message (-0x%04x)", ret);
                            ec = make_error_code(ErrorStatus_t::SIGNATURE_VERIFICATION_ERROR);
                        }
                        else
                        {
                            tr_debug("Signature valid");
                        }
                    }
                    free(md);
                }
                mbedtls_pk_free(&pk);
            }
            /**
             * Returns the algorithm name provided to the constructor
             * \return Algorithmname
             */
            std::string name() const
            {
                return m_algorithmName;
            }
        private:
            const std::string                 m_publicKey;
            const std::string                 m_privateKey; 
            const std::optional<std::string   m_publicKeyPassword; 
            const std::optional<std::string>  m_privateKeyPassword;
            const mbedtls_md_type_t           m_messageDigestAlgorithm; /// Hash generator 
            const std::string                 m_algorithmName;          /// Algorithmname
        };
        /**
         * Base class for ECDSA family of algorithms
         */
        struct ecdsa
        {
            /**
             * Construct new ecdsa algorithm
             * \param public_key ECDSA public key in PEM format
             * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
             * \param public_key_password Password to decrypt public key pem.
             * \param privat_key_password Password to decrypt private key pem.
             * \param md Pointer to hash function
             * \param name Name of the algorithm
             */
            ecdsa(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password, const EVP_MD*(*md)(), const std::string& name)
                : md(md), alg_name(name)
            {
                if (private_key.empty())
                {
                    std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
                    if ((size_t)BIO_write(pubkey_bio.get(), public_key.data(), public_key.size()) != public_key.size())
                        throw ecdsa_exception("failed to load public key: bio_write failed");

                    pkey.reset(PEM_read_bio_EC_PUBKEY(pubkey_bio.get(), nullptr, nullptr, (void*)public_key_password.c_str()), EC_KEY_free);
                    if (!pkey)
                        throw ecdsa_exception("failed to load public key: PEM_read_bio_EC_PUBKEY failed");
                }
                else
                {
                    std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
                    if ((size_t)BIO_write(privkey_bio.get(), private_key.data(), private_key.size()) != private_key.size())
                        throw ecdsa_exception("failed to load private key: bio_write failed");
                    pkey.reset(PEM_read_bio_ECPrivateKey(privkey_bio.get(), nullptr, nullptr, (void*)private_key_password.c_str()), EC_KEY_free);
                    if (!pkey)
                        throw ecdsa_exception("failed to load private key: PEM_read_bio_RSAPrivateKey failed");
                }

                if(EC_KEY_check_key(pkey.get()) == 0)
                    throw ecdsa_exception("failed to load key: key is invalid");
            }
            /**
             * Sign jwt data
             * \param data The data to sign
             * \return ECDSA signature for the given data
             * \throws signature_generation_exception
             */
            std::string sign(const std::string& data) const
            {
                const std::string hash = generate_hash(data);

                std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>
                sig(ECDSA_do_sign((const unsigned char*)hash.data(), hash.size(), pkey.get()), ECDSA_SIG_free);
                if(!sig)
                    throw signature_generation_exception();
#ifdef OPENSSL10

                return bn2raw(sig->r) + bn2raw(sig->s);
#else
                const BIGNUM *r;
                const BIGNUM *s;
                ECDSA_SIG_get0(sig.get(), &r, &s);
                return bn2raw(r) + bn2raw(s);
#endif
            }
            /**
             * Check if signature is valid
             * \param data The data to check signature against
             * \param signature Signature provided by the jwt
             * \throws signature_verification_exception If the provided signature does not match
             */
            void verify(const std::string& data, const std::string& signature) const
            {
                const std::string hash = generate_hash(data);
                auto r = raw2bn(signature.substr(0, signature.size() / 2));
                auto s = raw2bn(signature.substr(signature.size() / 2));

#ifdef OPENSSL10
                ECDSA_SIG sig;
                sig.r = r.get();
                sig.s = s.get();

                if(ECDSA_do_verify((const unsigned char*)hash.data(), hash.size(), &sig, pkey.get()) != 1)
                    throw signature_verification_exception("Invalid signature");
#else
                ECDSA_SIG *sig = ECDSA_SIG_new();

                ECDSA_SIG_set0(sig, r.get(), s.get());

                if(ECDSA_do_verify((const unsigned char*)hash.data(), hash.size(), sig, pkey.get()) != 1)
                    throw signature_verification_exception("Invalid signature");
#endif
            }
            /**
             * Returns the algorithm name provided to the constructor
             * \return Algorithmname
             */
            std::string name() const
            {
                return alg_name;
            }
        private:
            /**
             * Convert a OpenSSL BIGNUM to a std::string
             * \param bn BIGNUM to convert
             * \return bignum as string
             */
#ifdef OPENSSL10
            static std::string bn2raw(BIGNUM* bn)
#else
            static std::string bn2raw(const BIGNUM* bn)
#endif
            {
                std::string res;
                res.resize(BN_num_bytes(bn));
                BN_bn2bin(bn, (unsigned char*)res.data());
                if(res.size()%2 == 1 && res[0] == 0x00)
                    return res.substr(1);
                return res;
            }
            /**
             * Convert an std::string to a OpenSSL BIGNUM
             * \param raw String to convert
             * \return BIGNUM representation
             */
            static std::unique_ptr<BIGNUM, decltype(&BN_free)> raw2bn(const std::string& raw)
            {
                if(static_cast<uint8_t>(raw[0]) >= 0x80)
                {
                    std::string str(1, 0x00);
                    str += raw;
                    return std::unique_ptr<BIGNUM, decltype(&BN_free)>(BN_bin2bn((const unsigned char*)str.data(), str.size(), nullptr), BN_free);
                }
                return std::unique_ptr<BIGNUM, decltype(&BN_free)>(BN_bin2bn((const unsigned char*)raw.data(), raw.size(), nullptr), BN_free);
            }

            /**
             * Hash the provided data using the hash function specified in constructor
             * \param data Data to hash
             * \return Hash of data
             */
            std::string generate_hash(const std::string& data) const
            {
#ifdef OPENSSL10
                std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
#else
                std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
                if(EVP_DigestInit(ctx.get(), md()) == 0)
                    throw signature_generation_exception("EVP_DigestInit failed");
                if(EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 0)
                    throw signature_generation_exception("EVP_DigestUpdate failed");
                unsigned int len = 0;
                std::string res;
                res.resize(EVP_MD_CTX_size(ctx.get()));
                if(EVP_DigestFinal(ctx.get(), (unsigned char*)res.data(), &len) == 0)
                    throw signature_generation_exception("EVP_DigestFinal failed");
                res.resize(len);
                return res;
            }

            /// OpenSSL struct containing keys
            std::shared_ptr<EC_KEY> pkey;
            /// Hash generator function
            const EVP_MD*(*md)();
            /// Algorithmname
            const std::string alg_name;
        };
        /**
         * Base class for PSS-RSA family of algorithms
         */
        struct pss {
            /**
             * Construct new pss algorithm
             * \param public_key RSA public key in PEM format
             * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
             * \param public_key_password Password to decrypt public key pem.
             * \param privat_key_password Password to decrypt private key pem.
             * \param md Pointer to hash function
             * \param name Name of the algorithm
             */
            pss(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password, const EVP_MD*(*md)(), const std::string& name)
                : md(md), alg_name(name)
            {
                std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
                if ((size_t)BIO_write(pubkey_bio.get(), public_key.data(), public_key.size()) != public_key.size())
                    throw rsa_exception("failed to load public key: bio_write failed");
                pkey.reset(PEM_read_bio_PUBKEY(pubkey_bio.get(), nullptr, nullptr, (void*)public_key_password.c_str()), EVP_PKEY_free);
                if (!pkey)
                    throw rsa_exception("failed to load public key: PEM_read_bio_PUBKEY failed");

                if (!private_key.empty()) {
                    std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
                    if ((size_t)BIO_write(privkey_bio.get(), private_key.data(), private_key.size()) != private_key.size())
                        throw rsa_exception("failed to load private key: bio_write failed");
                    RSA* privkey = PEM_read_bio_RSAPrivateKey(privkey_bio.get(), nullptr, nullptr, (void*)private_key_password.c_str());
                    if (privkey == nullptr)
                        throw rsa_exception("failed to load private key: PEM_read_bio_RSAPrivateKey failed");
                    if (EVP_PKEY_assign_RSA(pkey.get(), privkey) == 0) {
                        RSA_free(privkey);
                        throw rsa_exception("failed to load private key: EVP_PKEY_assign_RSA failed");
                    }
                }
            }
            /**
             * Sign jwt data
             * \param data The data to sign
             * \return ECDSA signature for the given data
             * \throws signature_generation_exception
             */
            std::string sign(const std::string& data) const {
                auto hash = this->generate_hash(data);

                std::unique_ptr<RSA, decltype(&RSA_free)> key(EVP_PKEY_get1_RSA(pkey.get()), RSA_free);
                const int size = RSA_size(key.get());

                std::string padded(size, 0x00);
                if (!RSA_padding_add_PKCS1_PSS_mgf1(key.get(), (unsigned char*)padded.data(), (const unsigned char*)hash.data(), md(), md(), -1))  
                    throw signature_generation_exception("failed to create signature: RSA_padding_add_PKCS1_PSS_mgf1 failed");

                std::string res(size, 0x00);
                if (RSA_private_encrypt(size, (const unsigned char*)padded.data(), (unsigned char*)res.data(), key.get(), RSA_NO_PADDING) < 0)
                    throw signature_generation_exception("failed to create signature: RSA_private_encrypt failed");
                return res;
            }
            /**
             * Check if signature is valid
             * \param data The data to check signature against
             * \param signature Signature provided by the jwt
             * \throws signature_verification_exception If the provided signature does not match
             */
            void verify(const std::string& data, const std::string& signature) const {
                auto hash = this->generate_hash(data);

                std::unique_ptr<RSA, decltype(&RSA_free)> key(EVP_PKEY_get1_RSA(pkey.get()), RSA_free);
                const int size = RSA_size(key.get());
                
                std::string sig(size, 0x00);
                if(!RSA_public_decrypt(signature.size(), (const unsigned char*)signature.data(), (unsigned char*)sig.data(), key.get(), RSA_NO_PADDING))
                    throw signature_verification_exception("Invalid signature");
                
                if(!RSA_verify_PKCS1_PSS_mgf1(key.get(), (const unsigned char*)hash.data(), md(), md(), (const unsigned char*)sig.data(), -1))
                    throw signature_verification_exception("Invalid signature");
            }
            /**
             * Returns the algorithm name provided to the constructor
             * \return Algorithmname
             */
            std::string name() const {
                return alg_name;
            }
        private:
            /**
             * Hash the provided data using the hash function specified in constructor
             * \param data Data to hash
             * \return Hash of data
             */
            std::string generate_hash(const std::string& data) const {
#ifdef OPENSSL10
                std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
#else
                std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
                if(EVP_DigestInit(ctx.get(), md()) == 0)
                    throw signature_generation_exception("EVP_DigestInit failed");
                if(EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 0)
                    throw signature_generation_exception("EVP_DigestUpdate failed");
                unsigned int len = 0;
                std::string res;
                res.resize(EVP_MD_CTX_size(ctx.get()));
                if(EVP_DigestFinal(ctx.get(), (unsigned char*)res.data(), &len) == 0)
                    throw signature_generation_exception("EVP_DigestFinal failed");
                res.resize(len);
                return res;
            }
            
            /// OpenSSL structure containing keys
            std::shared_ptr<EVP_PKEY> pkey;
            /// Hash generator function
            const EVP_MD*(*md)();
            /// Algorithmname
            const std::string alg_name;
        };

        /**
         * HS256 algorithm
         */
        struct hs256 : public hmacsha {
            /**
             * Construct new instance of algorithm
             * \param key HMAC signing key
             */
            explicit hs256(std::string key)
                : hmacsha(std::move(key), MBEDTLS_MD_SHA256, "HS256")
            {}
        };
        /**
         * HS384 algorithm
         */
        struct hs384 : public hmacsha {
            /**
             * Construct new instance of algorithm
             * \param key HMAC signing key
             */
            explicit hs384(std::string key)
                : hmacsha(std::move(key), MBEDTLS_MD_SHA384, "HS384")
            {}
        };
        /**
         * HS512 algorithm
         */
        struct hs512 : public hmacsha {
            /**
             * Construct new instance of algorithm
             * \param key HMAC signing key
             */
            explicit hs512(std::string key)
                : hmacsha(std::move(key), MBEDTLS_MD_SHA512, "HS512")
            {}
        };
        /**
         * RS256 algorithm
         */
        struct rs256 : public rsa {
            /**
             * Construct new instance of algorithm
             * \param public_key RSA public key in PEM format
             * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
             * \param public_key_password Password to decrypt public key pem.
             * \param privat_key_password Password to decrypt private key pem.
             */
            rs256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
                : rsa(public_key, private_key, public_key_password, private_key_password, MBEDTLS_MD_SHA256, "RS256")
            {}
        };
        /**
         * RS384 algorithm
         */
        struct rs384 : public rsa {
            /**
             * Construct new instance of algorithm
             * \param public_key RSA public key in PEM format
             * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
             * \param public_key_password Password to decrypt public key pem.
             * \param privat_key_password Password to decrypt private key pem.
             */
            rs384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
                : rsa(public_key, private_key, public_key_password, private_key_password, MBEDTLS_MD_SHA384, "RS384")
            {}
        };
        /**
         * RS512 algorithm
         */
        struct rs512 : public rsa {
            /**
             * Construct new instance of algorithm
             * \param public_key RSA public key in PEM format
             * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
             * \param public_key_password Password to decrypt public key pem.
             * \param privat_key_password Password to decrypt private key pem.
             */
            rs512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
                : rsa(public_key, private_key, public_key_password, private_key_password, MBEDTLS_MD_SHA512, "RS512")
            {}
        };
        /**
         * ES256 algorithm
         */
        struct es256 : public ecdsa {
            /**
             * Construct new instance of algorithm
             * \param public_key ECDSA public key in PEM format
             * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
             * \param public_key_password Password to decrypt public key pem.
             * \param privat_key_password Password to decrypt private key pem.
             */
            es256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
                : ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "ES256")
            {}
        };
        /**
         * ES384 algorithm
         */
        struct es384 : public ecdsa {
            /**
             * Construct new instance of algorithm
             * \param public_key ECDSA public key in PEM format
             * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
             * \param public_key_password Password to decrypt public key pem.
             * \param privat_key_password Password to decrypt private key pem.
             */
            es384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
                : ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "ES384")
            {}
        };
        /**
         * ES512 algorithm
         */
        struct es512 : public ecdsa {
            /**
             * Construct new instance of algorithm
             * \param public_key ECDSA public key in PEM format
             * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
             * \param public_key_password Password to decrypt public key pem.
             * \param privat_key_password Password to decrypt private key pem.
             */
            es512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
                : ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "ES512")
            {}
        };

        /**
         * PS256 algorithm
         */
        struct ps256 : public pss {
            /**
             * Construct new instance of algorithm
             * \param public_key RSA public key in PEM format
             * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
             * \param public_key_password Password to decrypt public key pem.
             * \param privat_key_password Password to decrypt private key pem.
             */
            ps256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
                : pss(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "PS256")
            {}
        };
        /**
         * PS384 algorithm
         */
        struct ps384 : public pss {
            /**
             * Construct new instance of algorithm
             * \param public_key RSA public key in PEM format
             * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
             * \param public_key_password Password to decrypt public key pem.
             * \param privat_key_password Password to decrypt private key pem.
             */
            ps384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
                : pss(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "PS384")
            {}
        };
        /**
         * PS512 algorithm
         */
        struct ps512 : public pss {
            /**
             * Construct new instance of algorithm
             * \param public_key RSA public key in PEM format
             * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
             * \param public_key_password Password to decrypt public key pem.
             * \param privat_key_password Password to decrypt private key pem.
             */
            ps512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
                : pss(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "PS512")
            {}
        };
    }

    /**
     * Convenience wrapper for JSON value
     */
    class claim
    {
        picojson::value val;
    public:
        enum class type
        {
            null,
            boolean,
            number,
            string,
            array,
            object,
            int64
        };

        claim()
            : val()
        {}
#if JWT_CLAIM_EXPLICIT
        explicit claim(std::string s)
            : val(std::move(s))
        {}
        explicit claim(const date& s)
            : val(int64_t(std::chrono::system_clock::to_time_t(s)))
        {}
        explicit claim(const std::set<std::string>& s)
            : val(picojson::array(s.cbegin(), s.cend()))
        {}
        explicit claim(const picojson::value& val)
            : val(val)
        {}
#else
        claim(std::string s)
            : val(std::move(s))
        {}
        claim(const date& s)
            : val(int64_t(std::chrono::system_clock::to_time_t(s)))
        {}
        claim(const std::set<std::string>& s)
            : val(picojson::array(s.cbegin(), s.cend()))
        {}
        claim(const picojson::value& val)
            : val(val)
        {}
#endif

        /**
         * Get wrapped json object
         * \return Wrapped json object
         */
        picojson::value to_json() const
        {
            return val;
        }

        /**
         * Get type of contained object
         * \return Type
         * \throws std::logic_error An internal error occured
         */
        type get_type(std::error_code& ec) const
        {
            if (val.is<picojson::null>()) return type::null;
            else if (val.is<bool>()) return type::boolean;
            else if (val.is<int64_t>()) return type::int64;
            else if (val.is<double>()) return type::number;
            else if (val.is<std::string>()) return type::string;
            else if (val.is<picojson::array>()) return type::array;
            else if (val.is<picojson::object>()) return type::object;
            else 
            {
                tr_error("Unknown JSON type");
                ec = make_error_code(ErrorStatus_t::INTERNAL_LOGIC_ERROR);
                return type::null;
            }
        }

        /**
         * Get the contained object as a string
         * \return content as string
         * \throws std::bad_cast Content was not a string
         */
        const std::string& as_string(std::error_code& ec) const
        {
            if (!val.is<std::string>())
            {
                ec = make_error_code(ErrorStatus_t::BAD_CAST_STRING_ERROR);
                tr_error("%s :-> std::bad_cast error : %s", 
                          ec.category().name(), ec.message());
                return "";
            }
            return val.get<std::string>();
        }
        /**
         * Get the contained object as a date
         * \return content as date
         * \throws std::bad_cast Content was not a date
         */
        date as_date(std::error_code& ec) const
        {
            return std::chrono::system_clock::from_time_t(as_int(ec));
        }
        /**
         * Get the contained object as an array
         * \return content as array
         * \throws std::bad_cast Content was not an array
         */
        const picojson::array& as_array(std::error_code& ec) const
        {
            if (!val.is<picojson::array>())
            {
                ec = make_error_code(ErrorStatus_t::BAD_CAST_ARRAY_ERROR);
                tr_error("%s :-> std::bad_cast error : %s", 
                          ec.category().name(), ec.message());
                std::string emptyString("");
                return picojson::array(emptyString.cbegin(), emptyString.cend());
            }
            return val.get<picojson::array>();
        }
        /**
         * Get the contained object as a set of strings
         * \return content as set of strings
         * \throws std::bad_cast Content was not a set
         */
        const std::set<std::string> as_set(std::error_code& ec) const
        {
            std::set<std::string> res;
            for (auto& e : as_array())
            {
                if (!e.is<std::string>())
                {
                    ec = make_error_code(ErrorStatus_t::BAD_CAST_SET_ERROR);
                    tr_error("%s :-> std::bad_cast error : %s", 
                              ec.category().name(), ec.message());
                    return res;
                }
                res.insert(e.get<std::string>());
            }
            return res;
        }
        /**
         * Get the contained object as an integer
         * \return content as int
         * \throws std::bad_cast Content was not an int
         */
        int64_t as_int(std::error_code& ec) const
        {
            if (!val.is<int64_t>())
            {
                ec = make_error_code(ErrorStatus_t::BAD_CAST_INT_ERROR);
                tr_error("%s :-> std::bad_cast error : %s", 
                          ec.category().name(), ec.message());
                return 0;
            }
            return val.get<int64_t>();
        }
        /**
         * Get the contained object as a bool
         * \return content as bool
         * \throws std::bad_cast Content was not a bool
         */
        bool as_bool(std::error_code& ec) const
        {
            if (!val.is<bool>())
            {
                ec = make_error_code(ErrorStatus_t::BAD_CAST_BOOL_ERROR);
                tr_error("%s :-> std::bad_cast error : %s", 
                          ec.category().name(), ec.message());
                return false;
            }
            return val.get<bool>();
        }
        /**
         * Get the contained object as a number
         * \return content as double
         * \throws std::bad_cast Content was not a number
         */
        double as_number(std::error_code& ec) const
        {
            if (!val.is<double>())
            {
                ec = make_error_code(ErrorStatus_t::BAD_CAST_NUMBER_ERROR);
                tr_error("%s :-> std::bad_cast error : %s", 
                          ec.category().name(), ec.message());
                return 0.0;
            }
            return val.get<double>();
        }
    };

    /**
     * Base class that represents a token payload.
     * Contains Convenience accessors for common claims.
     */
    class payload
    {
    protected:
        std::unordered_map<std::string, claim> payload_claims;
    public:
        /**
         * Check if issuer is present ("iss")
         * \return true if present, false otherwise
         */
        bool has_issuer() const noexcept
        {
            return has_payload_claim("iss");
        }
        /**
         * Check if subject is present ("sub")
         * \return true if present, false otherwise
         */
        bool has_subject() const noexcept
        {
            return has_payload_claim("sub");
        }
        /**
         * Check if audience is present ("aud")
         * \return true if present, false otherwise
         */
        bool has_audience() const noexcept
        {
            return has_payload_claim("aud");
        }
        /**
         * Check if expires is present ("exp")
         * \return true if present, false otherwise
         */
        bool has_expires_at() const noexcept
        {
            return has_payload_claim("exp");
        }
        /**
         * Check if not before is present ("nbf")
         * \return true if present, false otherwise
         */
        bool has_not_before() const noexcept
        {
            return has_payload_claim("nbf");
        }
        /**
         * Check if issued at is present ("iat")
         * \return true if present, false otherwise
         */
        bool has_issued_at() const noexcept
        {
            return has_payload_claim("iat");
        }
        /**
         * Check if token id is present ("jti")
         * \return true if present, false otherwise
         */
        bool has_id() const noexcept
        {
            return has_payload_claim("jti");
        }
        /**
         * Get issuer claim
         * \return issuer as string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        const std::string& get_issuer(std::error_code& ec) const
        {
            auto claimN = get_payload_claim("iss", ec);
            if (!ec)
            { 
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Get subject claim
         * \return subject as string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        const std::string& get_subject(std::error_code& ec) const
        {
            auto claimN = get_payload_claim("sub", ec);
            if (!ec)
            { 
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Get audience claim
         * \return audience as a set of strings
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a set (Should not happen in a valid token)
         */
        std::set<std::string> get_audience(std::error_code& ec) const
        {
            auto claimN = get_payload_claim("aud", ec);
            if (!ec)
            { 
                return claimN.as_set(ec);
            }
            else
            {
                return std::set<std::string>();
            }
        }
        /**
         * Get expires claim
         * \return expires as a date in utc
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a date (Should not happen in a valid token)
         */
        const date get_expires_at(std::error_code& ec) const
        {
            auto claimN = get_payload_claim("exp", ec);
            if (!ec)
            { 
                return claimN.as_date(ec);
            }
            else
            {
                return std::chrono::system_clock::from_time_t(0);
            }
        }
        /**
         * Get not valid before claim
         * \return nbf date in utc
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a date (Should not happen in a valid token)
         */
        const date get_not_before(std::error_code& ec) const
        {
            auto claimN = get_payload_claim("nbf", ec);
            if (!ec)
            { 
                return claimN.as_date(ec);
            }
            else
            {
                return std::chrono::system_clock::from_time_t(0);
            }
        }
        /**
         * Get issued at claim
         * \return issued at as date in utc
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a date (Should not happen in a valid token)
         */
        const date get_issued_at(std::error_code& ec) const
        {
            auto claimN = get_payload_claim("iat", ec);
            if (!ec)
            { 
                return claimN.as_date(ec);
            }
            else
            {
                return std::chrono::system_clock::from_time_t(0);
            }
        }
        /**
         * Get id claim
         * \return id as string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        const std::string& get_id(std::error_code& ec) const
        {
            auto claimN = get_payload_claim("jti", ec);
            if (!ec)
            { 
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Check if a payload claim is present
         * \return true if claim was present, false otherwise
         */
        bool has_payload_claim(const std::string& name) const noexcept
        {
            return payload_claims.count(name) != 0;
        }
        /**
         * Get payload claim
         * \return Requested claim
         * \throws std::runtime_error If claim was not present
         */
        const claim& get_payload_claim(const std::string& name, std::error_code& ec) const
        {
            if (!has_payload_claim(name))
            {
                tr_error("Runtime error. Claim not found");
                ec = make_error_code(ErrorStatus_t::CLAIM_NOT_FOUND_ERROR);
                return claim(); 
            }
            return payload_claims.at(name);
        }
        /**
         * Get all payload claims
         * \return map of claims
         */
        std::unordered_map<std::string, claim> get_payload_claims() const
        {
            return payload_claims;
        }
    };

    /**
     * Base class that represents a token header.
     * Contains Convenience accessors for common claims.
     */
    class header
    {
    protected:
        std::unordered_map<std::string, claim> header_claims;
    public:
        /**
         * Check if algortihm is present ("alg")
         * \return true if present, false otherwise
         */
        bool has_algorithm() const noexcept
        {
            return has_header_claim("alg");
        }
        /**
         * Check if type is present ("typ")
         * \return true if present, false otherwise
         */
        bool has_type() const noexcept
        {
            return has_header_claim("typ");
        }
        /**
         * Check if content type is present ("cty")
         * \return true if present, false otherwise
         */
        bool has_content_type() const noexcept
        {
            return has_header_claim("cty");
        }
        /**
         * Check if key id is present ("kid")
         * \return true if present, false otherwise
         */
        bool has_key_id() const noexcept
        {
            return has_header_claim("kid");
        }
        /**
         * Get algorithm claim
         * \return algorithm as string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        const std::string& get_algorithm(std::error_code& ec) const
        {
            auto claimN = get_header_claim("alg", ec);
            if (!ec)
            { 
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Get type claim
         * \return type as a string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        const std::string& get_type(std::error_code& ec) const
        {
            auto claimN = get_header_claim("typ", ec);
            if (!ec)
            { 
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Get content type claim
         * \return content type as string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        const std::string& get_content_type(std::error_code& ec) const
        {            
            auto claimN = get_header_claim("cty", ec);
            if (!ec)
            { 
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Get key id claim
         * \return key id as string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        const std::string& get_key_id(std::error_code& ec) const
        {
            auto claimN = get_header_claim("kid", ec);
            if (!ec)
            { 
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Check if a header claim is present
         * \return true if claim was present, false otherwise
         */
        bool has_header_claim(const std::string& name) const noexcept
        {
            return header_claims.count(name) != 0;
        }
        /**
         * Get header claim
         * \return Requested claim
         * \throws std::runtime_error If claim was not present
         */
        const claim& get_header_claim(const std::string& name, std::error_code& ec) const
        {
            if (!has_header_claim(name))
            {
                tr_error("Runtime error. Claim not found");
                ec = make_error_code(ErrorStatus_t::CLAIM_NOT_FOUND_ERROR);
                return claim(); 
            }
            return header_claims.at(name);
        }
        /**
         * Get all header claims
         * \return map of claims
         */
        std::unordered_map<std::string, claim> get_header_claims() const
        {
            return header_claims;
        }
    };

    /**
     * Class containing all information about a decoded token
     */
    class decoded_jwt : public header, public payload
    {
    protected:
        /// Unmodifed token, as passed to constructor
        const std::string token;
        /// Header part decoded from base64
        std::string header;
        /// Unmodified header part in base64
        std::string header_base64;
        /// Payload part decoded from base64
        std::string payload;
        /// Unmodified payload part in base64
        std::string payload_base64;
        /// Signature part decoded from base64
        std::string signature;
        /// Unmodified signature part in base64
        std::string signature_base64;
    public:
        /**
         * Constructor
         * Parses a given token
         * \param token The token to parse
         * \throws std::invalid_argument Token is not in correct format
         * \throws std::runtime_error Base64 decoding failed or invalid json
         */
        explicit decoded_jwt(const std::string& token, std::error_code& errorCode)
            : token(token)
        {
            auto hdr_end = token.find('.');
            if (hdr_end == std::string::npos)
            {
                tr_error("Invalid token supplied");
                errorCode = make_error_code(ErrorStatus_t::INVALID_TOKEN_ARGUMENT_ERROR);
                return; 
            }
            auto payload_end = token.find('.', hdr_end + 1);
            if (payload_end == std::string::npos)
            {
                tr_error("Invalid token supplied");
                errorCode = make_error_code(ErrorStatus_t::INVALID_TOKEN_ARGUMENT_ERROR);
                return; 
            }
            header = header_base64 = token.substr(0, hdr_end);
            payload = payload_base64 = token.substr(hdr_end + 1, payload_end - hdr_end - 1);
            signature = signature_base64 = token.substr(payload_end + 1);

            // Fix padding: JWT requires padding to get removed
            auto fix_padding = [](std::string& str)
            {
                switch (str.size() % 4)
                {
                case 1:
                    str += alphabet::base64url::fill();
#ifdef __cpp_attributes
#if __has_cpp_attribute(fallthrough)
                    [[fallthrough]];
#endif
#endif
                case 2:
                    str += alphabet::base64url::fill();
#ifdef __cpp_attributes
#if __has_cpp_attribute(fallthrough)
                    [[fallthrough]];
#endif
#endif
                case 3:
                    str += alphabet::base64url::fill();
#ifdef __cpp_attributes
#if __has_cpp_attribute(fallthrough)
                    [[fallthrough]];
#endif
#endif
                default:
                    break;
                }
            };
            fix_padding(header);
            fix_padding(payload);
            fix_padding(signature);

            std::error_code ec1;
            std::error_code ec2;
            std::error_code ec3;
            header = base::decode<alphabet::base64url>(header, ec1);
            payload = base::decode<alphabet::base64url>(payload, ec2);
            signature = base::decode<alphabet::base64url>(signature, ec3);
            
            if (ec1)
            {
                tr_error("Runtime_error Base64 decoding failed");
                errorCode = make_error_code(ErrorStatus_t::INVALID_INPUT_RUNTIME_ERROR);
                return;
            }
            else if (ec2)
            {
                tr_error("Runtime_error Base64 decoding failed");
                errorCode = make_error_code(ErrorStatus_t::INVALID_INPUT_RUNTIME_ERROR);
                return;
            }
            else if (ec3)
            {
                tr_error("Runtime_error Base64 decoding failed");
                errorCode = make_error_code(ErrorStatus_t::INVALID_INPUT_RUNTIME_ERROR);
                return;
            }

            auto parse_claims = [](const std::string& str, std::error_code& ec)
            {
                std::unordered_map<std::string, claim> res;
                picojson::value val;
                if (!picojson::parse(val, str).empty())
                {
                    tr_error("Invalid JSON detected");
                    ec = make_error_code(ErrorStatus_t::INVALID_JSON_DETECTED_ERROR);
                    return res; 
                }

                for (auto& e : val.get<picojson::object>())
                {
                    res.insert({ e.first, claim(e.second) });
                }

                return res;
            };

            header_claims = parse_claims(header, errorCode);
            if (!errorCode)
            {
                payload_claims = parse_claims(payload, errorCode);
            }
        }

        /**
         * Get token string, as passed to constructor
         * \return token as passed to constructor
         */
        const std::string& get_token() const
        {
            return token;
        }
        /**
         * Get header part as json string
         * \return header part after base64 decoding
         */
        const std::string& get_header() const
        {
            return header;
        }
        /**
         * Get payload part as json string
         * \return payload part after base64 decoding
         */
        const std::string& get_payload() const
        {
            return payload;
        }
        /**
         * Get signature part as json string
         * \return signature part after base64 decoding
         */
        const std::string& get_signature() const
        {
            return signature;
        }
        /**
         * Get header part as base64 string
         * \return header part before base64 decoding
         */
        const std::string& get_header_base64() const
        {
            return header_base64;
        }
        /**
         * Get payload part as base64 string
         * \return payload part before base64 decoding
         */
        const std::string& get_payload_base64() const
        {
            return payload_base64;
        }
        /**
         * Get signature part as base64 string
         * \return signature part before base64 decoding
         */
        const std::string& get_signature_base64() const
        {
            return signature_base64;
        }

    };

    /**
     * Builder class to build and sign a new token
     * Use jwt::create() to get an instance of this class.
     */
    class builder
    {
        std::unordered_map<std::string, claim> header_claims;
        std::unordered_map<std::string, claim> payload_claims;

        builder() {}
        friend builder create();
    public:
        /**
         * Set a header claim.
         * \param id Name of the claim
         * \param c Claim to add
         * \return *this to allow for method chaining
         */
        builder& set_header_claim(const std::string& id, claim c)
        {
            header_claims[id] = std::move(c);
            return *this;
        }
        /**
         * Set a payload claim.
         * \param id Name of the claim
         * \param c Claim to add
         * \return *this to allow for method chaining
         */
        builder& set_payload_claim(const std::string& id, claim c)
        {
            payload_claims[id] = std::move(c);
            return *this;
        }
        /**
         * Set algorithm claim
         * You normally don't need to do this, as the algorithm is automatically set if you don't change it.
         * \param str Name of algorithm
         * \return *this to allow for method chaining
         */
        builder& set_algorithm(const std::string& str)
        {
            return set_header_claim("alg", claim(str));
        }
        /**
         * Set type claim
         * \param str Type to set
         * \return *this to allow for method chaining
         */
        builder& set_type(const std::string& str)
        {
            return set_header_claim("typ", claim(str));
        }
        /**
         * Set content type claim
         * \param str Type to set
         * \return *this to allow for method chaining
         */
        builder& set_content_type(const std::string& str)
        {
            return set_header_claim("cty", claim(str));
        }
        /**
         * Set key id claim
         * \param str Key id to set
         * \return *this to allow for method chaining
         */
        builder& set_key_id(const std::string& str)
        {
            return set_header_claim("kid", claim(str));
        }
        /**
         * Set issuer claim
         * \param str Issuer to set
         * \return *this to allow for method chaining
         */
        builder& set_issuer(const std::string& str)
        {
            return set_payload_claim("iss", claim(str));
        }
        /**
         * Set subject claim
         * \param str Subject to set
         * \return *this to allow for method chaining
         */
        builder& set_subject(const std::string& str)
        {
            return set_payload_claim("sub", claim(str));
        }
        /**
         * Set audience claim
         * \param l Audience set
         * \return *this to allow for method chaining
         */
        builder& set_audience(const std::set<std::string>& l)
        {
            return set_payload_claim("aud", claim(l));
        }
        /**
         * Set expires at claim
         * \param d Expires time
         * \return *this to allow for method chaining
         */
        builder& set_expires_at(const date& d)
        {
            return set_payload_claim("exp", claim(d));
        }
        /**
         * Set not before claim
         * \param d First valid time
         * \return *this to allow for method chaining
         */
        builder& set_not_before(const date& d)
        {
            return set_payload_claim("nbf", claim(d));
        }
        /**
         * Set issued at claim
         * \param d Issued at time, should be current time
         * \return *this to allow for method chaining
         */
        builder& set_issued_at(const date& d)
        {
            return set_payload_claim("iat", claim(d));
        }
        /**
         * Set id claim
         * \param str ID to set
         * \return *this to allow for method chaining
         */
        builder& set_id(const std::string& str)
        {
            return set_payload_claim("jti", claim(str));
        }

        /**
         * Sign token and return result
         * \param algo Instance of an algorithm to sign the token with
         * \return Final token as a string
         */
        template<typename T>
        std::string sign(const T& algo)
        {
            this->set_algorithm(algo.name());

            picojson::object obj_header;
            for (auto& e : header_claims)
            {
                obj_header.insert({ e.first, e.second.to_json() });
            }
            picojson::object obj_payload;
            for (auto& e : payload_claims)
            {
                obj_payload.insert({ e.first, e.second.to_json() });
            }

            auto encode = [](const std::string& data)
            {
                auto base = base::encode<alphabet::base64url>(data);
                auto pos = base.find(alphabet::base64url::fill());
                base = base.substr(0, pos);
                return base;
            };

            std::string header = encode(picojson::value(obj_header).serialize());
            std::string payload = encode(picojson::value(obj_payload).serialize());

            std::string token = header + "." + payload;

            return token + "." + encode(algo.sign(token));
        }
    };

    /**
     * Verifier class used to check if a decoded token contains all claims required by your application and has a valid signature.
     */
    template<typename Clock>
    class verifier
    {
        struct algo_base
        {
            virtual ~algo_base() = default;
            virtual void verify(const std::string& data, const std::string& sig) = 0;
        };
        template<typename T>
        struct algo : public algo_base
        {
            T alg;
            explicit algo(T a) : alg(a) {}
            virtual void verify(const std::string& data, const std::string& sig) override
            {
                alg.verify(data, sig);
            }
        };

        /// Required claims
        std::unordered_map<std::string, claim> claims;
        /// Leeway time for exp, nbf and iat
        size_t default_leeway = 0;
        /// Instance of clock type
        Clock clock;
        /// Supported algorithms
        std::unordered_map<std::string, std::shared_ptr<algo_base>> algs;
    public:
        /**
         * Constructor for building a new verifier instance
         * \param c Clock instance
         */
        explicit verifier(Clock c) : clock(c) {}

        /**
         * Set default leeway to use.
         * \param leeway Default leeway to use if not specified otherwise
         * \return *this to allow chaining
         */
        verifier& leeway(size_t leeway)
        {
            default_leeway = leeway;
            return *this;
        }
        /**
         * Set leeway for expires at.
         * If not specified the default leeway will be used.
         * \param leeway Set leeway to use for expires at.
         * \return *this to allow chaining
         */
        verifier& expires_at_leeway(size_t leeway)
        {
            return with_claim("exp", claim(std::chrono::system_clock::from_time_t(leeway)));
        }
        /**
         * Set leeway for not before.
         * If not specified the default leeway will be used.
         * \param leeway Set leeway to use for not before.
         * \return *this to allow chaining
         */
        verifier& not_before_leeway(size_t leeway)
        {
            return with_claim("nbf", claim(std::chrono::system_clock::from_time_t(leeway)));
        }
        /**
         * Set leeway for issued at.
         * If not specified the default leeway will be used.
         * \param leeway Set leeway to use for issued at.
         * \return *this to allow chaining
         */
        verifier& issued_at_leeway(size_t leeway)
        {
            return with_claim("iat", claim(std::chrono::system_clock::from_time_t(leeway)));
        }
        /**
         * Set an issuer to check for.
         * Check is casesensitive.
         * \param iss Issuer to check for.
         * \return *this to allow chaining
         */
        verifier& with_issuer(const std::string& iss)
        {
            return with_claim("iss", claim(iss));
        }
        /**
         * Set a subject to check for.
         * Check is casesensitive.
         * \param sub Subject to check for.
         * \return *this to allow chaining
         */
        verifier& with_subject(const std::string& sub)
        {
            return with_claim("sub", claim(sub));
        }
        /**
         * Set an audience to check for.
         * If any of the specified audiences is not present in the token the check fails.
         * \param aud Audience to check for.
         * \return *this to allow chaining
         */
        verifier& with_audience(const std::set<std::string>& aud)
        {
            return with_claim("aud", claim(aud));
        }
        /**
         * Set an id to check for.
         * Check is casesensitive.
         * \param id ID to check for.
         * \return *this to allow chaining
         */
        verifier& with_id(const std::string& id)
        {
            return with_claim("jti", claim(id));
        }
        /**
         * Specify a claim to check for.
         * \param name Name of the claim to check for
         * \param c Claim to check for
         * \return *this to allow chaining
         */
        verifier& with_claim(const std::string& name, claim c)
        {
            claims[name] = c;
            return *this;
        }

        /**
         * Add an algorithm available for checking.
         * \param alg Algorithm to allow
         * \return *this to allow chaining
         */
        template<typename Algorithm>
        verifier& allow_algorithm(Algorithm alg)
        {
            algs[alg.name()] = std::make_shared<algo<Algorithm>>(alg);
            return *this;
        }

        /**
         * Verify the given token.
         * \param jwt Token to check
         * \throws token_verification_exception Verification failed
         */
        void verify(const decoded_jwt& jwt, std::error_code& errCode) const
        {
            const std::string data = jwt.get_header_base64() + "." + jwt.get_payload_base64();
            const std::string sig = jwt.get_signature();
            const std::string& algo = jwt.get_algorithm();
            if (algs.count(algo) == 0)
            {
                tr_error("Wrong algorithm");
                errCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                return;
            }
            algs.at(algo)->verify(data, sig);

            auto assert_claim_eq = [](const decoded_jwt& jwt, 
                                      const std::string& key, 
                                      const claim& c, 
                                      std::error_code& errorCode)
            {
                if (!jwt.has_payload_claim(key))
                {
                    tr_error("Decoded_jwt is missing %s claim", key.c_str());
                    errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                    return;
                }
                auto& jc = jwt.get_payload_claim(key);
                std::error_code ec1;
                std::error_code ec2;
                auto type1 = jc.get_type(ec1);
                auto type2 = c.get_type(ec2);

                if (ec1)
                {
                    tr_error("Decoded_jwt could not be parsed");
                    errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                    return;                    
                }
                else if (ec2)
                {
                    tr_error("Expected claim could not be parsed");
                    errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                    return;
                }           
                else if (type1 != type2)
                {
                    tr_error("Claim %s type mismatch", key.c_str());
                    errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                    return; 
                }
                if (type2 == claim::type::int64)
                {
                    std::error_code ec1;
                    std::error_code ec2;
                    auto date1 = jc.as_date(ec1);
                    auto date2 = c.as_date(ec2);
                    if (ec1)
                    {
                        tr_error("Decoded_date could not be parsed");
                        errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                        return;                    
                    }
                    else if (ec2)
                    {
                        tr_error("Expected date could not be parsed");
                        errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                        return;
                    }
                    else if (date1 != date2)
                    {
                        tr_error("Claim %s does not match expected", key.c_str());
                        errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                        return; 
                    }
                }
                else if (type2 == claim::type::array)
                {
                    std::error_code ec1;
                    std::error_code ec2;
                    auto s1 = jc.as_set(ec1);
                    auto s2 = c.as_set(ec2);
                    if (ec1)
                    {
                        tr_error("Decoded_set could not be parsed");
                        errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                        return;                    
                    }
                    else if (ec2)
                    {
                        tr_error("Expected set could not be parsed");
                        errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                        return;
                    }
                    else if (s1.size() != s2.size())
                    {
                        tr_error("Claim %s does not match expected", key.c_str());
                        errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                        return;
                    }
                    auto it1 = s1.cbegin();
                    auto it2 = s2.cbegin();
                    while (it1 != s1.cend() && it2 != s2.cend())
                    {
                        if (*it1++ != *it2++)
                        {
                            tr_error("Claim %s does not match expected", key.c_str());
                            errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                            return;
                        }
                    }
                }
                else if (type2 == claim::type::string)
                {
                    std::error_code ec1;
                    std::error_code ec2;
                    auto s1 = jc.as_string(ec1);
                    auto s2 = c.as_string(ec2);
                    if (ec1)
                    {
                        tr_error("Decoded_string could not be parsed");
                        errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                        return;                    
                    }
                    else if (ec2)
                    {
                        tr_error("Expected string could not be parsed");
                        errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                        return;
                    }
                    if (s1 != s2)
                    {
                        tr_error("Claim %s does not match expected", key.c_str());
                        errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                        return;
                    }
                }
                else 
                {
                    tr_error("Internal error");
                    errorCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                    return;
                }
            };

            auto time = clock.now();

            if (jwt.has_expires_at())
            {
                std::error_code ec;
                auto claimsDate = claims.at("exp").as_date(ec);
                if (ec)
                {
                    tr_error("Expected_expiry date could not be parsed");
                    errCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                    return;                    
                }
            
                auto leeway = claims.count("exp") == 1 ? std::chrono::system_clock::to_time_t(claimsDate) : default_leeway;
                auto exp = jwt.get_expires_at();
                if (time > exp + std::chrono::seconds(leeway))
                {
                    tr_error("Token expired");
                    errCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                    return; 
                }
            }
            if (jwt.has_issued_at())
            {
                std::error_code ec;
                auto claimsDate = claims.at("iat").as_date(ec);
                if (ec)
                {
                    tr_error("Expected_issued at date could not be parsed");
                    errCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                    return;                    
                }
                
                auto leeway = claims.count("iat") == 1 ? std::chrono::system_clock::to_time_t(claimsDate) : default_leeway;
                auto iat = jwt.get_issued_at();
                if (time < iat - std::chrono::seconds(leeway))
                {
                    tr_error("Token expired");
                    errCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                    return;
                }
            }
            if (jwt.has_not_before())
            {
                std::error_code ec;
                auto claimsDate = claims.at("nbf").as_date(ec);
                if (ec)
                {
                    tr_error("Expected_not before date could not be parsed");
                    errCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                    return;                    
                }
                
                auto leeway = claims.count("nbf") == 1 ? std::chrono::system_clock::to_time_t(claimsDate) : default_leeway;
                auto nbf = jwt.get_not_before();
                if (time < nbf - std::chrono::seconds(leeway))
                {
                    tr_error("Token expired");
                    errCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                    return;
                }
            }
            for (auto& c : claims)
            {
                if (c.first == "exp" || c.first == "iat" || c.first == "nbf")
                {
                    // Nothing to do here, already checked
                }
                else if (c.first == "aud")
                {
                    if (!jwt.has_audience())
                    {
                        tr_error("Token does not contain the required audience");
                        errCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                        return;
                    }
                    
                    std::error_code ec;
                    auto aud = jwt.get_audience();
                    auto expected = c.second.as_set(ec);
                    if (ec)
                    {
                        tr_error("Expected_audience set could not be parsed");
                        errCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                        return;                    
                    }
                    else
                    {
                        for (auto& e : expected)
                        {
                            if (aud.count(e) == 0)
                            {
                                tr_error("Token does not contain the required audience");
                                errCode = make_error_code(ErrorStatus_t::TOKEN_VERIFICATION_ERROR);
                                return;
                            }
                        }
                    }
                }
                else
                {
                    assert_claim_eq(jwt, c.first, c.second, errCode);
                }
            }
        }
    };

    /**
     * Create a verifier using the given clock
     * \param c Clock instance to use
     * \return verifier instance
     */
    template<typename Clock>
    verifier<Clock> verify(Clock c)
    {
        return verifier<Clock>(c);
    }

    /**
     * Default clock class using std::chrono::system_clock as a backend.
     */
    struct default_clock
    {
        std::chrono::system_clock::time_point now() const
        {
            return std::chrono::system_clock::now();
        }
    };

    /**
     * Create a verifier using the default clock
     * \return verifier instance
     */
    inline verifier<default_clock> verify()
    {
        return verify<default_clock>({});
    }

    /**
     * Return a builder instance to create a new token
     */
    inline builder create()
    {
        return builder();
    }

    /**
     * Decode a token
     * \param token Token to decode
     * \return Decoded token
     * \throws std::invalid_argument Token is not in correct format
     * \throws std::runtime_error Base64 decoding failed or invalid json
     */
    inline decoded_jwt decode(const std::string& token)
    {
        return decoded_jwt(token);
    }
}
