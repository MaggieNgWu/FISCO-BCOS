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
/** @file SDFSM2Signature.cpp
 * @author maggiewu
 * @date 2021-02-01
 */
#include "SDFSM2Signature.h"
#include "SDFCryptoProvider.h"
#include "libdevcore/Common.h"
#include "libdevcrypto/Common.h"
#include "libdevcrypto/SM2Signature.h"
#include "libdevcrypto/sm2/sm2.h"
#include "libsdf/swsds.h"

using namespace std;
using namespace dev;
using namespace dev::crypto;

std::shared_ptr<crypto::Signature> dev::crypto::SDFSM2Sign(
    KeyPair const& _keyPair, const h256& _hash)
{
    // clock_t start = clock();
    // cout << "@@@@ SDFSM2Sign start " << endl;
    // get provider
    SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
    unsigned char signature[64];
    unsigned int signLen;
    Key key(_keyPair);
    h256 privk((byte const*)key.PrivateKey(),
        FixedHash<32>::ConstructFromPointerType::ConstructFromPointer);
    // clock_t step1 = clock();
    // cout << "@@@@ SDFSM2Sign step 1 prepare key and HSM , duration: " << step1 - start << endl;

    // According to the SM2 standard
    // step 1 : calculate M' = Za || M
    // step 2 : e = H(M')
    // step 3 : signature = Sign(e)
    // get provider
    BIGNUM* res = NULL;
    size_t zValueLen;
    unsigned char zValue[SM3_DIGEST_LENGTH];
    zValueLen = sizeof(zValue);
    res = BN_new();
    if (res == NULL)
    {
        throw "[SM2::sign] malloc BigNumber failed";
    }
    string pri = toHex(bytesConstRef{_keyPair.secret().data(), 32});
    BN_hex2bn(&res, (const char *)pri.c_str());
    EC_KEY* sm2Key = EC_KEY_new_by_curve_name(NID_sm2);
    EC_KEY_set_private_key(sm2Key, res);
    if (!SM2::sm2GetZ(pri, (const EC_KEY*)sm2Key, zValue, zValueLen))
    {
        throw "Error Of Compute Z";
    }
    //clock_t step2 = clock();
    //cout << "@@@@ SDFSM2Sign step 2 getz , duration: " << step2 - step1 << endl;
    
    // step 2 : e = H(M')
    unsigned char hashResult[SM3_DIGEST_LENGTH];
    unsigned int uiHashResultLen;
    unsigned int code = provider.HashWithZ(SM3, (const char*)zValue, zValueLen,
        (const char*)_hash.data(), SM3_DIGEST_LENGTH, (unsigned char*)hashResult, &uiHashResultLen);
    if (code != SDR_OK)
    {
        throw provider.GetErrorMessage(code);
    }

    // step 3 : signature = Sign(e)
    //clock_t step3 = clock();
    //cout << "@@@@ SDFSM2Sign step 3 SM3(Z|M) , duration: " << step3 - step2 << endl;
    code = provider.Sign(key, SM2, (const unsigned char*)hashResult, 32, signature, &signLen);
    if (code != SDR_OK)
    {
        throw provider.GetErrorMessage(code);
    }
    // clock_t step4 = clock();
    // cout << "@@@@ SDFSM2Sign step 4 Sign , duration: " << step4 - step3 << endl;
    h256 r((byte const*)signature, FixedHash<32>::ConstructFromPointerType::ConstructFromPointer);
    h256 s((byte const*)(signature + 32),
        FixedHash<32>::ConstructFromPointerType::ConstructFromPointer);
    // clock_t step5 = clock();
    // cout << "@@@@ SDFSM2Sign step 5 finish , duration: " << step5 - step4 << endl;
    return make_shared<SM2Signature>(r, s, _keyPair.pub());
}

bool dev::crypto::SDFSM2Verify(
    h512 const& _pubKey, std::shared_ptr<crypto::Signature> _sig, const h256& _hash)
{
    //clock_t start = clock();
    //cout << "@@@@ SDFSM2Verify start " << start << endl;
    // get provider
    SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
    
    // parse input
    // cout << "pub key: " << toHex(bytesConstRef{_pubKey.ref().data(), 64}) << endl;
    char emptyPrivateKey[32];
    Key key((unsigned char*)emptyPrivateKey, (unsigned char*)_pubKey.ref().data());
    bool verifyResult;
    
    //clock_t step1 = clock();
    //cout << "@@@@ SDFSM2Verify step 1 prepare key and HSM , duration: " << step1 - start << endl;
    
    
    // cout << "key.pub " << toHex(bytesConstRef{key.PublicKey(), 64}) << endl;
    // cout << "sig:" << toHex(bytesConstRef{_sig->asBytes().data(), 64}) << endl;
    // cout << "hash.ref.data:" << toHex(bytesConstRef{_hash.ref().data(), 32}) << endl;

    // Get Z
    EC_KEY* sm2Key = NULL;
    EC_POINT* pubPoint = NULL;
    EC_GROUP* sm2Group = NULL;
    unsigned char zValue[SM3_DIGEST_LENGTH];
    size_t zValueLen = SM3_DIGEST_LENGTH;
    std::string pubHex = toHex(_pubKey.data(), _pubKey.data() + 64, "04");
    sm2Group = EC_GROUP_new_by_curve_name(NID_sm2);
    if ((pubPoint = EC_POINT_new(sm2Group)) == NULL)
    {
        throw "[SDFSM2::verify] ERROR of Verify EC_POINT_new";
    }
    if (!EC_POINT_hex2point(sm2Group, (const char*)pubHex.c_str(), pubPoint, NULL))
    {
        throw "[SDFSM2::verify] ERROR of Verify EC_POINT_hex2point";
    }  
    sm2Key = EC_KEY_new_by_curve_name(NID_sm2);
    if (!EC_KEY_set_public_key(sm2Key, pubPoint))
    {
        throw "[SDFSM2::verify] ERROR of Verify EC_KEY_set_public_key";
    }
    if (!ECDSA_sm2_get_Z((const EC_KEY*)sm2Key, NULL, NULL, 0, zValue, &zValueLen))
    {
        throw "[SDFSM2::verify] Error Of Compute Z";
    }
    //clock_t step2 = clock();
    //cout << "@@@@ SDFSM2Verify step 2 getz, duration:  " << step2 - step1 << endl;
    
    unsigned char hashResult[SM3_DIGEST_LENGTH];
    unsigned int uiHashResultLen;
    unsigned int code = provider.HashWithZ(SM3, (const char*)zValue, zValueLen,
        (const char*)_hash.data(), SM3_DIGEST_LENGTH, (unsigned char*)hashResult, &uiHashResultLen);
    if (code != SDR_OK)
    {
        throw provider.GetErrorMessage(code);
    }

    //clock_t step3 = clock();
    //cout << "@@@@ SDFSM2Verify step 3 SM3(Z|M), duration: " << step3 - step2 << endl;
    
    // cout << "hash(hash):" << toHex(bytesConstRef{(const unsigned char*)hashResult, 32}) << endl;
    code = provider.Verify(
        key, SM2, (const unsigned char*)hashResult, 32, _sig->asBytes().data(), 64, &verifyResult);
    //clock_t step4 = clock();
    //cout << "@@@@ SDFSM2Verify step 4 Verify finish, duration: " << step4 - step3 << endl;
    // cout << _pubKey << _sig->r << _hash<<endl;
    if (code == SDR_OK)
    {
        return true;
    }
    else if (code == SDR_VERIFYERR)
    {
        return false;
    }
    else
    {
        throw provider.GetErrorMessage(code);
    }
}

h512 dev::crypto::SDFSM2Recover(std::shared_ptr<crypto::Signature> _s, h256 const& _message)
{
    auto _sig = dynamic_pointer_cast<SM2Signature>(_s);
    if (!_sig)
    {
        return h512{};
    }

    if (!_sig->isValid())
    {
        return h512{};
    }
    if (SDFSM2Verify(_sig->v, _sig, _message))
    {
        return _sig->v;
    }
    return h512{};
}