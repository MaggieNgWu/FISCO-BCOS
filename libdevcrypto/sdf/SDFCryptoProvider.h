/*
    This file is part of FISCO-BCOS.

    FISCO-BCOS is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    FISCO-BCOS is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with FISCO-BCOS.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file SDFCryptoProvider.h
 * @author maggiewu
 * @date 2021-02-01
 */
#pragma once
#include "libdevcrypto/Common.h"
#include "libsdf/swsds.h"
#include <cstring>
#include <iostream>
#include <string>
#include <mutex>
#define CRYPTO_LOG(LEVEL) LOG(LEVEL) << "[CRYPTO] "

using namespace std;
namespace dev
{
class KeyPair;
namespace crypto
{
enum AlgorithmType : uint32_t
{
    SM2 = 0x00020100,      // SGD_SM2_1
    SM3 = 0x00000001,      // SGD_SM3
    SM4_CBC = 0x00002002,  // SGD_SM4_CBC
};

class Key
{
public:
    unsigned char* PublicKey() const { return m_publicKey; }
    unsigned char* PrivateKey() const { return m_privateKey; }
    Key(void){};
    Key(KeyPair const& keyPair)
    {
        m_privateKey = (unsigned char*)keyPair.secret().ref().data();
        m_publicKey = (unsigned char*)keyPair.pub().ref().data();
    };
    Key(unsigned char* privateKey, unsigned char* publicKey)
    {
        //cout << "init a key" << endl;
        m_privateKey = privateKey;
        m_publicKey = publicKey;
    };
    Key(const unsigned int keyIndex, std::string& password)
    {
        m_keyIndex = keyIndex;
        m_keyPassword = password;
    };
    unsigned int Identifier() { return m_keyIndex; };
    std::string Password() { return m_keyPassword; };
    void setPrivateKey(unsigned char* privateKey, unsigned int len)
    {
        m_privateKey = (unsigned char*)malloc(len * sizeof(char));
        strncpy((char*)m_privateKey, (char*)privateKey, len);
    };
    void setPublicKey(unsigned char* publicKey, unsigned int len)
    {
        m_publicKey = (unsigned char*)malloc(len * sizeof(char));
        strncpy((char*)m_publicKey, (char*)publicKey, len);
    };

private:
    unsigned int m_keyIndex;
    std::string m_keyPassword;
    unsigned char* m_privateKey;
    unsigned char* m_publicKey;
};

/**
 *  SDFCryptoProvider suply SDF function calls
 *  Singleton
 */
class SDFCryptoProvider
{
private:
    SGD_HANDLE m_deviceHandle;
    SGD_HANDLE m_sessionHandle;
    SDFCryptoProvider();
    ~SDFCryptoProvider();
    SDFCryptoProvider(const SDFCryptoProvider&);
    SDFCryptoProvider& operator=(const SDFCryptoProvider&);
    std::mutex mut;
public:
    /**
     * Return the instance
     */
    static SDFCryptoProvider& GetInstance();

    unsigned int PrintDeviceInfo();
    /**
     * Generate key
     * Return error code
     */
    unsigned int KeyGen(AlgorithmType algorithm, Key* key);

    /**
     * Sign
     */
    unsigned int Sign(Key const& key, AlgorithmType algorithm, unsigned char const* digest,
        unsigned int const digestLen, unsigned char* signature, unsigned int* signatureLen);

    /**
     * Verify signature
     */
    unsigned int Verify(Key const& key, AlgorithmType algorithm, unsigned char const* digest,
        unsigned int const digestLen, unsigned char const* signature,
        unsigned int const signatureLen, bool* result);

    /**
     * Make hash
     */
    unsigned int Hash(AlgorithmType algorithm, char const* message, unsigned int const messageLen,
        unsigned char* digest, unsigned int* digestLen);

    /**
     * Encrypt
     */
    unsigned int Encrypt(Key const& key, AlgorithmType algorithm, unsigned char const* plantext,
        unsigned int const plantextLen, unsigned char* cyphertext, unsigned int* cyphertextLen);

    /**
     * Decrypt
     */
    unsigned int Decrypt(Key const& key, AlgorithmType algorithm, unsigned char const* cyphertext,
        unsigned int const cyphertextLen, unsigned char* plantext, unsigned int* plantextLen);

    /**
     * Make sm3 hash with z value
     */
    unsigned int HashWithZ(AlgorithmType algorithm,char const* zValue, unsigned int const zValueLen, char const* message, unsigned int const messageLen,
        unsigned char* digest, unsigned int* digestLen);

    static std::string GetErrorMessage(SGD_RV code);
};
}  // namespace crypto
}  // namespace dev
