#include "SDFCryptoProvider.h"
#include "libdevcore/CommonData.h"
#include "libsdf/swsds.h"
#include <libdevcore/Guards.h>
#include <cstring>
#include <iostream>

using namespace std;

namespace dev
{
namespace crypto
{
SDFCryptoProvider::SDFCryptoProvider()
{
    SGD_RV deviceStatus = SDF_OpenDevice(&m_deviceHandle);
    if (deviceStatus != SDR_OK)
    {
        CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] ERROR of open device."
                          << LOG_KV("message", GetErrorMessage(deviceStatus));
        throw deviceStatus;
    }
    m_sessionPool = new SessionPool(10,m_deviceHandle);
    CRYPTO_LOG(INFO) << "[SDF::SDFCryptoProvider] Finish HSM open device.";
}

SDFCryptoProvider::~SDFCryptoProvider()
{
    delete m_sessionPool;
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
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        ECCrefPrivateKey eccKey;
        eccKey.bits = 32 * 8;
        memcpy(eccKey.D, key.PrivateKey(), 32);
        SGD_RV signCode = SDF_ExternalSign_ECC(sessionHandle, SGD_SM2_1, &eccKey,
            (SGD_UCHAR*)digest, digestLen, (ECCSignature*)signature);
        if (signCode != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] failed make sign."
                              << LOG_KV("message", GetErrorMessage(signCode));
            m_sessionPool->ReturnSession(sessionHandle);
            return signCode;
        }
        *signatureLen = 64;
        m_sessionPool->ReturnSession(sessionHandle);
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
        ECCrefPublicKey pk;
        ECCrefPrivateKey sk;
        SGD_UINT32 keyLen = 256;

        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_RV result = SDF_GenerateKeyPair_ECC(sessionHandle, SGD_SM2_3, keyLen, &pk, &sk);
        if (result != SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return result;
        }
        std::basic_string<unsigned char> pk_x = pk.x;
        std::basic_string<unsigned char> pk_y = pk.y;
        std::basic_string<unsigned char> pk_xy = pk_x + pk_y;
        key->setPrivateKey(sk.D, sk.bits / 8);
        key->setPublicKey((unsigned char*)pk_xy.c_str(), pk.bits / 4);
        m_sessionPool->ReturnSession(sessionHandle);
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
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_RV code = SDF_HashInit(sessionHandle, SGD_SM3, NULL, NULL, 0);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] Hash.SDF_HashInit fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }

        code = SDF_HashUpdate(sessionHandle, (SGD_UCHAR*)message, messageLen);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] Hash.SDF_HashUpdate fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }

        code = SDF_HashFinal(sessionHandle, (SGD_UCHAR*)digest, digestLen);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] Hash.SDF_HashFinal fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }
        m_sessionPool->ReturnSession(sessionHandle);
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
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_RV code = SDF_HashInit(sessionHandle, SGD_SM3, NULL, NULL, 0);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] HashWithZ.SDF_HashInit fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }
        code = SDF_HashUpdate(sessionHandle, (SGD_UCHAR*)zValue, zValueLen);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] HashWithZ.SDF_HashUpdate fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }

        code = SDF_HashUpdate(sessionHandle, (SGD_UCHAR*)message, messageLen);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] HashWithZ.SDF_HashUpdate fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }

        code = SDF_HashFinal(sessionHandle, (SGD_UCHAR*)digest, digestLen);
        if (code != SDR_OK)
        {
            CRYPTO_LOG(ERROR) << "[SDF::SDFCryptoProvider] HashWithZ.SDF_HashFinal fialed."
                              << LOG_KV("message", GetErrorMessage(code));
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }
        m_sessionPool->ReturnSession(sessionHandle);
        return code;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::PrintDeviceInfo()
{
    SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
    DEVICEINFO stDeviceInfo;
    SGD_RV code = SDF_GetDeviceInfo(sessionHandle, &stDeviceInfo);
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
    m_sessionPool->ReturnSession(sessionHandle);
    return code;
}
unsigned int SDFCryptoProvider::Verify(Key const& key, AlgorithmType algorithm,
    unsigned char const* digest, unsigned int const digestLen, unsigned char const* signature,
    const unsigned int signatureLen, bool* result)
{
    switch (algorithm)
    {
    case SM2:
    {
        if (signatureLen != 64)
        {
            return SDR_NOTSUPPORT;
        }
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        ECCrefPublicKey eccKey;
        eccKey.bits = 32 * 8;
        memcpy(eccKey.x, key.PublicKey(), 32);
        memcpy(eccKey.y, key.PublicKey() + 32, 32);
        ECCSignature eccSignature;
        memcpy(eccSignature.r, signature, 32);
        memcpy(eccSignature.s, signature + 32, 32);
        SGD_RV code = SDF_ExternalVerify_ECC(
            sessionHandle, SGD_SM2_1, &eccKey, (SGD_UCHAR*)digest, digestLen, &eccSignature);
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
        m_sessionPool->ReturnSession(sessionHandle);
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
        return "unkown code " + std::to_string(code);
    }
}

}  // namespace crypto
}  // namespace dev
