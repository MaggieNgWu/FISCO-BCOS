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
    size_t loopRound = atoi(argv[1]);
    initSMCrypto();
    g_BCOSConfig.setUseSMCrypto(true);
    KeyPair keyPair = KeyPair::create();
    getchar();
    std::cout << "#### begin test" << std::endl;

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
              << ",  duration(s) : " << (float)(end - start) / CLOCKS_PER_SEC << endl;
    std::cout << "Times per second: " << loopRound / ((float)(end - start) / CLOCKS_PER_SEC) << endl
              << endl;


    std::cout << "### test SDF sm3" << std::endl;
    start = clock();
    for (size_t i = 0; i < loopRound; i++)
    {
        SDFSM3(input);
    }
    end = clock();

    std::cout << "Number of calculate round: " << loopRound
              << ",  duration(s) : " << (float)(end - start) / CLOCKS_PER_SEC << endl;
    std::cout << "Times per second: " << loopRound / ((float)(end - start) / CLOCKS_PER_SEC) << endl
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
              << ",  duration(s) : " << (float)(end - start) / CLOCKS_PER_SEC << endl;
    std::cout << "Times per second: " << loopRound / ((float)(end - start) / CLOCKS_PER_SEC) << endl
              << endl;

    std::cout << "### test SDF sm2 sign" << std::endl;
    start = clock();
    for (size_t i = 0; i < loopRound; i++)
    {
        SDFSM2Sign(keyPair, hash);
    }
    end = clock();
    std::cout << "Number of calculate round: " << loopRound
              << ",  duration(s) : " << (float)(end - start) / CLOCKS_PER_SEC << endl;
    std::cout << "Times per second: " << loopRound / ((float)(end - start) / CLOCKS_PER_SEC) << endl
              << endl;

    std::cout << "### test sm2 verify" << std::endl;
    auto signatureResult = Sign(keyPair, hash);
    start = clock();
    for (size_t i = 0; i < loopRound; i++)
    {
        sm2Verify(keyPair.pub(), signatureResult, hash);
    }
    end = clock();
    std::cout << "Number of calculate round: " << loopRound
              << ",  duration(s) : " << (float)(end - start) / CLOCKS_PER_SEC << endl;
    std::cout << "Times per second: " << loopRound / ((float)(end - start) / CLOCKS_PER_SEC) << endl
              << endl;

    std::cout << "### test SDF sm2 verify" << std::endl;
    start = clock();
    for (size_t i = 0; i < loopRound; i++)
    {
        SDFSM2Verify(keyPair.pub(), signatureResult, hash);
    }
    end = clock();
    std::cout << "Number of calculate round: " << loopRound
              << ",  duration(s) : " << (float)(end - start) / CLOCKS_PER_SEC << endl;
    std::cout << "Times per second: " << loopRound / ((float)(end - start) / CLOCKS_PER_SEC) << endl
              << endl;
    std::cout << "#### test end" << std::endl;
    getchar();
}