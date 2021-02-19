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
/** @file SDFCrypto.h
 * @author maggie
 * @date 2021-02-01
 */

#include <libdevcrypto/sdf/SDFSM3Hash.h>
#include <libdevcrypto/sdf/SDFSM2Signature.h>
#include <libdevcrypto/SM2Signature.h>
#include <libdevcrypto/Common.h>
#include <libdevcore/Assertions.h>
#include <libdevcore/CommonJS.h>
#include <test/tools/libutils/TestOutputHelper.h>
#include <boost/test/unit_test.hpp>

using namespace std;
using namespace dev;
using namespace dev::crypto;
namespace dev
{
namespace test
{
BOOST_FIXTURE_TEST_SUITE(SDF, SM_CryptoTestFixture)
// test sdf sm3
BOOST_AUTO_TEST_CASE(SM_testSDFSha256)
{
    const std::string plainText = "123456ABC+";
    const std::string cipherText =
        "0x68b5bae5fe19851624298fd1e9b4d788627ac27c13aad3240102ffd292a17911";
    bytes bs;
    for (size_t i = 0; i < plainText.length(); i++)
    {
        bs.push_back((byte)plainText[i]);
    }
    bytesConstRef bsConst(&bs);
    BOOST_CHECK(toJS(SDFSM3(bsConst)) == cipherText);
    bytes b=fromHex("68b5bae5fe19851624298fd1e9b4d788627ac27c13aad3240102ffd292a17911");
    bytesConstRef newPlainText{(const unsigned char *)b.data(),32};
    h256 sdfResult = SDFSM3(newPlainText);
    h256 smResult = sm3(newPlainText);		    
    BOOST_CHECK(toJS(sdfResult) == toJS(smResult));
}
// test sdf sm2 sign
BOOST_AUTO_TEST_CASE(SM_testSDFSign)
{
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
BOOST_CHECK_EQUAL(result1,true);
BOOST_CHECK_EQUAL(result2,true);
BOOST_CHECK_EQUAL(result3,true);
BOOST_CHECK_EQUAL(result4,true);
}

BOOST_AUTO_TEST_SUITE_END()
}
}
