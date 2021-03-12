/*
    This file is part of fisco-bcos.

    fisco-bcos is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    fisco-bcos is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with fisco-bcos.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * @file: mini-crypto.cpp
 * @author: yujiechen
 *
 * @date: 2021
 */

#include <libdevcrypto/Common.h>
#include <libdevcrypto/CryptoInterface.h>
#include <libdevcrypto/Hash.h>
#include <libdevcrypto/SM2Signature.h>
#include <libdevcrypto/SM3Hash.h>
#include <libdevcrypto/sdf/SDFSM2Signature.h>
#include <libdevcrypto/sdf/SDFSM3Hash.h>
using namespace dev::crypto;
using namespace dev;
int main(int, const char* argv[])
{
    std::cout << "#### begin function test" << std::endl;
    KeyPair kp = KeyPair::create();
    h256 h(fromHex("0x68b5bae5fe19851624298fd1e9b4d788627ac27c13aad3240102ffd292a17911"));
    cout << "$$$h.ref.data: "<<toHex(bytesConstRef{ h.ref().data(),32})<< endl;
    std::shared_ptr<crypto::Signature> swResult = sm2Sign(kp,h);
    std::shared_ptr<crypto::Signature>  sdfResult = SDFSM2Sign(kp,h);	
    cout<< "$$$$signature r: "<< sdfResult->r << " s:" << sdfResult->s << endl;
    cout<< "*** Check signature"<<endl;
    cout<< "&&&&&&&&&&&&&&&&&&&&&"<<endl;
    bool result1 = sm2Verify(kp.pub(),swResult,h);
    cout<< "*** sm2Verify swResult :"<< result1 <<endl;
    cout<< "&&&&&&&&&&&&&&&&&&&&&"<<endl;
    bool result2 = sm2Verify(kp.pub(),sdfResult,h);
    cout<<"*** call sm2Verify sdfResult： "<< result2 <<endl;
    cout<< "&&&&&&&&&&&&&&&&&&&&&"<<endl;
    bool result3 = SDFSM2Verify(kp.pub(),sdfResult,h);
    cout <<"*** call sdfVerify sdfResult: "<< result3 <<endl;
    cout<< "&&&&&&&&&&&&&&&&&&&&&"<<endl;
    bool result4 = SDFSM2Verify(kp.pub(),swResult,h);
    cout <<"*** call sdfVerify swResult: "<< result4 <<endl;

    cout << "soft sign, soft verify, result: " << result1 << endl;
    cout << "hsm sign, soft verify, result: " << result2 << endl;
    cout << "hsm sign, hsm verify, result: " << result3 << endl;
    cout << "soft sign, hsm verify, result: " << result3 << endl;

    size_t loopRound = atoi(argv[1]);
    initSMCrypto();
    g_BCOSConfig.setUseSMCrypto(true);
    KeyPair keyPair = KeyPair::create();
    getchar();
    std::cout << "#### begin performance test" << std::endl;

    // calculate hash
    std::cout << "### test sm3" << std::endl;
    clock_t start = clock();
    std::string input = "test_sm3";
    for (size_t i = 0; i < loopRound; i++)
    {
        sm3(input);
    }
    clock_t end = clock();
    std::cout << "Number of calculate round: " << loopRound
              << ",  duration(s) : " << (double)(end - start) / CLOCKS_PER_SEC << endl;
    std::cout << "Times per second: " << loopRound / ((double)(end - start) / CLOCKS_PER_SEC) << endl
              << endl;


    std::cout << "### test SDF sm3" << std::endl;
    start = clock();
    for (size_t i = 0; i < loopRound; i++)
    {
        SDFSM3(input);
    }
    end = clock();
    std::cout << "Number of calculate round: " << loopRound
              << ",  duration(s) : " << (double)(end - start) / CLOCKS_PER_SEC << endl;
    std::cout << "Times per second: " << loopRound / ((double)(end - start) / CLOCKS_PER_SEC) << endl
              << endl;

    std::cout << "### test sm2 sign" << std::endl;
    auto hash = sm3(input);
    start = clock();
    for (size_t i = 0; i < loopRound; i++)
    {
        sm2Sign(keyPair, hash);
    }
    end = clock();
    std::cout << "Number of calculate round: " << loopRound
              << ",  duration(s) : " << (double)(end - start) / CLOCKS_PER_SEC << endl;
    std::cout << "Times per second: " << loopRound / ((double)(end - start) / CLOCKS_PER_SEC) << endl
              << endl;

    std::cout << "### test SDF sm2 sign" << std::endl;
    start = clock();
    for (size_t i = 0; i < loopRound; i++)
    {

        SDFSM2Sign(keyPair, hash);
    }
    end = clock();
    std::cout << "Number of calculate round: " << loopRound
              << ",  duration(s) : " << (double)(end - start) / CLOCKS_PER_SEC << endl;
    std::cout << "Times per second: " << loopRound / ((double)(end - start) / CLOCKS_PER_SEC) << endl
              << endl;

    auto signatureResult = sm2Sign(keyPair, hash);
    std::cout << "### test sm2 verify" << std::endl;
    start = clock();
    for (size_t i = 0; i < loopRound; i++)
    {
        sm2Verify(keyPair.pub(), signatureResult, hash);
    }
    end = clock();
    std::cout << "Number of calculate round: " << loopRound
              << ",  duration(s) : " << (double)(end - start) / CLOCKS_PER_SEC << endl;
    std::cout << "Times per second: " << loopRound / ((double)(end - start) / CLOCKS_PER_SEC) << endl
              << endl;

    std::cout << "### test SDF sm2 verify" << std::endl;
    start = clock();
    for (size_t i = 0; i < loopRound; i++)
    {
        SDFSM2Verify(keyPair.pub(), signatureResult, hash);
    }
    end = clock();
    std::cout << "Number of calculate round: " << loopRound
              << ",  duration(s) : " << (double)(end - start) / CLOCKS_PER_SEC << endl;
    std::cout << "Times per second: " << loopRound / ((double)(end - start) / CLOCKS_PER_SEC) << endl
              << endl;
    std::cout << "#### test end" << std::endl;
    getchar();
}

