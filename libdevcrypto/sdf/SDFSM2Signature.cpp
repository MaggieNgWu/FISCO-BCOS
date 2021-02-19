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
    // get provider
    SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
    // cout << "### Sign" << endl;
    unsigned char* signature = (unsigned char*)malloc(64);
    unsigned int signLen;
    Key key(_keyPair);
    // cout << "#### keyPair.secret " << toHex(bytesConstRef{_keyPair.secret().data(), 32}) << endl;
    h256 privk((byte const*)key.PrivateKey(),
        FixedHash<32>::ConstructFromPointerType::ConstructFromPointer);

    // cout << "#### key.priv " << privk << endl;
    // cout << "#### Call Sign" << endl;

    // According to the SM2 standard
    // step 1 : calculate M' = Za || M
    // step 2 : e = H(M')
    // step 3 : signature = Sin(e)
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
    // cout<<"1111111"<<endl;
    BN_hex2bn(&res, (const char *)pri.c_str());
    EC_KEY* sm2Key = EC_KEY_new_by_curve_name(NID_sm2);
    EC_KEY_set_private_key(sm2Key, res);
    // cout<<"222222"<<endl;
    if (!SM2::sm2GetZ(pri, (const EC_KEY*)sm2Key, zValue, zValueLen))
    {
        throw "Error Of Compute Z";
    }
    // cout<<"z value: "<<toHex(bytesConstRef{zValue,32}) <<endl;
    unsigned char hashResult[SM3_DIGEST_LENGTH];
    unsigned int uiHashResultLen;
    unsigned int code = provider.HashWithZ(SM3, (const char*)zValue, zValueLen,
        (const char*)_hash.data(), SM3_DIGEST_LENGTH, (unsigned char*)hashResult, &uiHashResultLen);
    if (code != SDR_OK)
    {
        throw provider.GetErrorMessage(code);
    }

    code = provider.Sign(key, SM2, (const unsigned char*)hashResult, 32, signature, &signLen);
    // cout << "##### code = " << code << endl;
    if (code != SDR_OK)
    {
        throw provider.GetErrorMessage(code);
    }
    // cout << "keyPair.pub " << toHex(bytesConstRef{_keyPair.pub().data(), 64}) << endl;
    char sign_s[32];
    memcpy(sign_s, signature + 32, 32);
    // cout << "signature : " << toHex(bytesConstRef{(const unsigned char*)signature, 64}) << endl;
    h256 r((byte const*)signature, FixedHash<32>::ConstructFromPointerType::ConstructFromPointer);
    h256 s((byte const*)(signature + 32),
        FixedHash<32>::ConstructFromPointerType::ConstructFromPointer);
    return make_shared<SM2Signature>(r, s, _keyPair.pub());
}

bool dev::crypto::SDFSM2Verify(
    h512 const& _pubKey, std::shared_ptr<crypto::Signature> _sig, const h256& _hash)
{
    // get provider
    SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
    // parse input
    // cout << "pub key: " << toHex(bytesConstRef{_pubKey.ref().data(), 64}) << endl;
    char emptyPrivateKey[32];
    Key key((unsigned char*)emptyPrivateKey, (unsigned char*)_pubKey.ref().data());
    bool verifyResult;
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
        throw "[SM2::veify] ERROR of Verify EC_POINT_new";
    }
    if (!EC_POINT_hex2point(sm2Group, (const char*)pubHex.c_str(), pubPoint, NULL))
    {
        throw "[SM2::veify] ERROR of Verify EC_POINT_hex2point";
    }  
    sm2Key = EC_KEY_new_by_curve_name(NID_sm2);
    if (!EC_KEY_set_public_key(sm2Key, pubPoint))
    {
        throw "[SM2::veify] ERROR of Verify EC_KEY_set_public_key";
    }
    if (!ECDSA_sm2_get_Z((const EC_KEY*)sm2Key, NULL, NULL, 0, zValue, &zValueLen))
    {
        throw "[SM2::veify] Error Of Compute Z";
    }

    unsigned char hashResult[SM3_DIGEST_LENGTH];
    unsigned int uiHashResultLen;
    unsigned int code = provider.HashWithZ(SM3, (const char*)zValue, zValueLen,
        (const char*)_hash.data(), SM3_DIGEST_LENGTH, (unsigned char*)hashResult, &uiHashResultLen);
    if (code != SDR_OK)
    {
        throw provider.GetErrorMessage(code);
    }
    
    // cout << "hash(hash):" << toHex(bytesConstRef{(const unsigned char*)hashResult, 32}) << endl;
    code = provider.Verify(
        key, SM2, (const unsigned char*)hashResult, 32, _sig->asBytes().data(), 64, &verifyResult);
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
