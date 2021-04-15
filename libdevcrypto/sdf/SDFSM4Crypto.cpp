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
/** @file SDFSM4Crypto.cpp
 * @author maggie
 * @date 2021-04-02
 */
#include "SDFSM4Crypto.h"
#include "SDFCryptoProvider.h"

using namespace std;
using namespace dev;
using namespace crypto;

std::string SDFSM4Encrypt(const unsigned char* _plainData, size_t _plainDataSize,
    const unsigned char* _key, size_t _keySize, const unsigned char* _ivData){
        Key key = Key();
        key.setPrivateKey((unsigned char *)_key,_keySize);
        SDFCryptoProvider provider = SDFCryptoProvider::GetInstance();
        unsigned int size;
        provider.Encrypt(key,SM4_CBC,_plainData,_plainDataSize,(unsigned char *)_ivData,&size);
}
std::string SDFSM4Decrypt(const unsigned char* _cypherData, size_t _cypherDataSize,
    const unsigned char* _key, size_t _keySize, const unsigned char* _ivData){
        Key key = Key();
        key.setPrivateKey((unsigned char *)_key,_keySize);
        SDFCryptoProvider provider = SDFCryptoProvider::GetInstance();
        unsigned int size;
        provider.Decrypt(key,SM4_CBC,_cypherData,_cypherDataSize,(unsigned char *)_ivData,&size);
}
