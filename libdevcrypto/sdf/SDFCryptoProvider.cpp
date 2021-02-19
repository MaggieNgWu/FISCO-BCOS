#include "SDFCryptoProvider.h"
#include "libdevcore/CommonData.h"
#include "libsdf/swsds.h"
#include <cstring>
#include <iostream>

using namespace std;

namespace dev
{
namespace crypto
{
SDFCryptoProvider::SDFCryptoProvider()
{
    cout << "open device" << endl;
    SGD_RV deviceStatus = SDF_OpenDevice(&m_deviceHandle);
    if (deviceStatus != SDR_OK)
    {
        CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] ERROR of open device."
                          << LOG_KV("message", GetErrorMessage(deviceStatus));
        throw deviceStatus;
    }
    SGD_RV sessionStatus = SDF_OpenSession(m_deviceHandle, &m_sessionHandle);
    if (sessionStatus != SDR_OK)
    {
        CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] ERROR of open session failed."
                          << LOG_KV("message", GetErrorMessage(deviceStatus));
        throw sessionStatus;
    }
    cout << "finish hsm initialization." << endl;
}

SDFCryptoProvider::~SDFCryptoProvider()
{
    if (m_sessionHandle != NULL)
    {
        SDF_CloseSession(m_sessionHandle);
    }
    if (m_deviceHandle != NULL)
    {
        SDF_CloseDevice(m_deviceHandle);
    }
}

SDFCryptoProvider& SDFCryptoProvider::GetInstance()
{
    static SDFCryptoProvider instance;
    return instance;
}

unsigned int SDFCryptoProvider::Sign(Key const& key, AlgorithmType algorithm,
    unsigned char const* digest, unsigned int const digestLen, unsigned char* signature,
    unsigned int* signatureLen)
{
    switch (algorithm)
    {
    case SM2:
    {
        ECCrefPrivateKey eccKey;
        eccKey.bits = 32 * 8;
        strncpy((char*)eccKey.D, (const char*)key.PrivateKey(), 32);
        unsigned char tmpData[512];
        memset(tmpData, 0, sizeof(tmpData));
        SGD_RV signCode = SDF_ExternalSign_ECC(m_sessionHandle, SGD_SM2_1, &eccKey,
            (SGD_UCHAR*)digest, digestLen, (ECCSignature*)tmpData);
        if (signCode != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] failed make sign."
                              << LOG_KV("message", GetErrorMessage(signCode));
            return signCode;
        }
        memcpy(signature, tmpData, 64);
        // strncpy((char*)signature, (const char*)tmpData, 64);
        *signatureLen = 512;
        return SDR_OK;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::KeyGen(AlgorithmType algorithm, Key* key)
{
    switch (algorithm)
    {
    case SM2:
    {
        // key
        ECCrefPublicKey pk;
        ECCrefPrivateKey sk;
        SGD_UINT32 keyLen = 256;

        // call generate key
        SGD_RV result = SDF_GenerateKeyPair_ECC(m_sessionHandle, SGD_SM2_3, keyLen, &pk, &sk);
        if (result != SDR_OK)
        {
            return result;
        }
        std::basic_string<unsigned char> pk_x = pk.x;
        std::basic_string<unsigned char> pk_y = pk.y;
        std::basic_string<unsigned char> pk_xy = pk_x + pk_y;
        key->setPrivateKey(sk.D, sk.bits / 8);
        key->setPublicKey((unsigned char*)pk_xy.c_str(), pk.bits / 4);
        return SDR_OK;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::Hash(AlgorithmType algorithm, char const* message,
    unsigned int const messageLen, unsigned char* digest, unsigned int* digestLen)
{
    switch (algorithm)
    {
    case SM3:
    {
        SGD_RV code = SDF_HashInit(m_sessionHandle, SGD_SM3, NULL, NULL, 0);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] SDF_HashInit fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            return code;
        }

        code = SDF_HashUpdate(m_sessionHandle, (SGD_UCHAR*)message, messageLen);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] SDF_HashUpdate fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            return code;
        }

        code = SDF_HashFinal(m_sessionHandle, (SGD_UCHAR*)digest, digestLen);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] SDF_HashFinal fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            return code;
        }
        return code;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}
unsigned int SDFCryptoProvider::HashWithZ(AlgorithmType algorithm, char const* zValue,
    unsigned int const zValueLen, char const* message, unsigned int const messageLen,
    unsigned char* digest, unsigned int* digestLen)
{
    switch (algorithm)
    {
    case SM3:
    {
        SGD_RV code = SDF_HashInit(m_sessionHandle, SGD_SM3, NULL, NULL, 0);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] SDF_HashInit fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            return code;
        }
        code = SDF_HashUpdate(m_sessionHandle, (SGD_UCHAR*)zValue, zValueLen);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] SDF_HashUpdate fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            return code;
        }

        code = SDF_HashUpdate(m_sessionHandle, (SGD_UCHAR*)message, messageLen);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] SDF_HashUpdate fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            return code;
        }

        code = SDF_HashFinal(m_sessionHandle, (SGD_UCHAR*)digest, digestLen);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] SDF_HashFinal fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            return code;
        }
        return code;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::PrintDeviceInfo()
{
    DEVICEINFO stDeviceInfo;
    SGD_RV code = SDF_GetDeviceInfo(m_sessionHandle, &stDeviceInfo);
    if (code == SDR_OK)
    {
        CRYPTO_LOG(INFO) << "[SDF::SDFCryptoProvider] Get Device Info."
                         << LOG_KV("device name", stDeviceInfo.DeviceName);
    }
    else
    {
        CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] Get Device Info."
                          << LOG_KV("error", GetErrorMessage(code));
    }
    return code;
}
unsigned int SDFCryptoProvider::Verify(Key const& key, AlgorithmType algorithm,
    unsigned char const* digest, unsigned int const digestLen, unsigned char const* signature,
    const unsigned int signatureLen, bool* result)
{
    cout << "@@Start verify signature" << endl;
    cout << "@@Params are key.public: " << toHex(bytesConstRef{key.PublicKey(), 64})
         << " hash: " << toHex(bytesConstRef{digest, 32})
         << " signature:" << toHex(bytesConstRef{signature, 64}) << "digestLen:" << digestLen
         << " signatureLen:" << signatureLen << endl;
    switch (algorithm)
    {
    case SM2:
    {
        if (signatureLen != 64)
        {
            return SDR_NOTSUPPORT;
        }
        ECCrefPublicKey eccKey;
        eccKey.bits = 32 * 8;
        cout << "verify" << endl;

        memcpy(eccKey.x, key.PublicKey(), 32);
        memcpy(eccKey.y, key.PublicKey() + 32, 32);
        // strncpy((char*)eccKey.x, (const char*)key.PublicKey(), 32);
        // strncpy((char*)eccKey.y, (const char*)key.PublicKey() + 32, 32);
        cout << "Get key, x:" << toHex(bytesConstRef{(const unsigned char*)eccKey.x, 32})
             << " y:" << toHex(bytesConstRef{(const unsigned char*)eccKey.y, 32}) << endl;
        // cout << "Get key:"<< toHex(bytesConstRef{(const unsigned char*)&eccKey.x,32}
        // <<toHex(bytesConstRef{(const unsigned char*)eccKey.y,32}) << enddl;
        ECCSignature eccSignature;
        memcpy(eccSignature.r, signature, 32);
        memcpy(eccSignature.s, signature + 32, 32);
        // strncpy((char*)eccSignature.r, (const char*)signature, 32);
        // strncpy((char*)eccSignature.s, (const char*)signature + 32, 32);
        cout << "Get signature: " << toHex(bytesConstRef{(const unsigned char*)eccSignature.r, 32})
             << toHex(bytesConstRef{(const unsigned char*)eccSignature.s, 32}) << endl;
        SGD_RV code = SDF_ExternalVerify_ECC(
            m_sessionHandle, SGD_SM2_1, &eccKey, (SGD_UCHAR*)digest, digestLen, &eccSignature);
        if (code == SDR_OK)
        {
            *result = true;
        }
        else
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] verify ecc signature."
                              << LOG_KV("result", GetErrorMessage(code));
            *result = false;
        }
        return code;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

std::string SDFCryptoProvider::GetErrorMessage(SGD_RV code)
{
    switch (code)
    {
    case SDR_OK:
        return "success";
    case SDR_UNKNOWERR:
        return "unknown error";
    case SDR_NOTSUPPORT:
        return "not support";
    case SDR_COMMFAIL:
        return "communication failed";
    case SDR_OPENDEVICE:
        return "failed open device";
    case SDR_OPENSESSION:
        return "failed open session";
    case SDR_PARDENY:
        return "permission deny";
    case SDR_KEYNOTEXIST:
        return "key not exit";
    case SDR_ALGNOTSUPPORT:
        return "algorithm not support";
    case SDR_ALGMODNOTSUPPORT:
        return "algorithm not support mode";
    case SDR_PKOPERR:
        return "public key calculate error";
    case SDR_SKOPERR:
        return "private key calculate error";
    case SDR_SIGNERR:
        return "signature error";
    case SDR_VERIFYERR:
        return "verify signature error";
    case SDR_SYMOPERR:
        return "symmetric crypto calculate error";
    case SDR_STEPERR:
        return "step error";
    case SDR_FILESIZEERR:
        return "file size error";
    case SDR_FILENOEXIST:
        return "file not exist";
    case SDR_FILEOFSERR:
        return "file offset error";
    case SDR_KEYTYPEERR:
        return "key type not right";
    case SDR_KEYERR:
        return "key error";
    default:
        return "unkown";
    }
}

}  // namespace crypto
}  // namespace dev
