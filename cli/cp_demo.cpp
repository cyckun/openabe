#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include "common.h"

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

int main(int argc, char **argv) {

  string inputStr;
  string input_file = "security.docx";

  string outputStr;
  string output_file = "security.cpabe";

  string xiaomingStr;
  string xiaoming_outputfile = "OK_xiaoming.security.docx";

  string xiaohongStr;
  string xiaohong_outputfile = "failed_xiaohong.security.docx";

  string xiaoliStr;
  string xiaoli_outputfile = "OK_xiaoli.security.docx";

  //read file 
  try {
    getFile(inputStr, input_file);
    size_t inputLen = inputStr.size();
    if (inputLen == 0 || inputLen > MAX_FILE_SIZE) {
      cerr << "input file is either empty or too big! Can encrypt up to 4GB files." << endl;
      return -1;
    }
  } catch(const std::ios_base::failure& e) {
    cerr << e.what() << endl;
    return -1;
  }



  InitializeOpenABE();

  cout << "cp-abe test" << endl;

  OpenABECryptoContext cpabe("CP-ABE");

  //generate mpk and msk
  cpabe.generateParams();

  string mpk;
  cpabe.exportPublicParams(mpk); //mpk is output, and keyblob of publicParams;

  string msk;
  cpabe.exportSecretParams(msk);

  //load 
  cpabe.importPublicParams(mpk);
  cpabe.importSecretParams(msk);


  //encrypt doc file
  cpabe.encrypt("(((Dept:SecurityResearch) or (level >= 4 )) and (Company:ByteDance))", inputStr, outputStr);

  //generate user key
  cpabe.keygen("Dept:SecurityResearch|level = 2| Company:ByteDance", "xiaomingCP");
  string key_xiaoming;
  cpabe.exportUserKey("xiaomingCP", key_xiaoming);

  cpabe.keygen("Dept:SecurityEvaluation|level = 2| Company:ByteDance", "xiaohongCP");
  string key_xiaohong;
  cpabe.exportUserKey("xiaohongCP", key_xiaohong);

  cpabe.keygen("Dept:IES|level = 4|Company:ByteDance", "xiaoliCP");
  string key_xiaoli;
  cpabe.exportUserKey("xiaoliCP", key_xiaoli); // key_xiaoli is output, keyblob;


  //===========decrypt=================//

  //xiaoming-decrypt
  bool result_xiaoming = cpabe.decrypt("xiaomingCP", outputStr, xiaomingStr);
  if (result_xiaoming && inputStr == xiaomingStr)
  {
    cout<<"xiaoming: decrypt success" <<endl;
    WriteBinaryFile(xiaoming_outputfile.c_str(), (uint8_t *)xiaomingStr.c_str(), xiaomingStr.size());

  }else {
    cout<<"xiaoming : decrypt failed" <<endl;
  }


  //xiaohong-decrypt
  bool result_xiaohong = cpabe.decrypt("xiaohongCP", outputStr, xiaohongStr);
  if (result_xiaohong && inputStr == xiaohongStr)
  {
    cout<<"xiaohong: decrypt success" <<endl;
    WriteBinaryFile(xiaohong_outputfile.c_str(), (uint8_t *)xiaohongStr.c_str(), xiaohongStr.size());

  }else {
    cout<<"xiaohong : decrypt failed" <<endl;
  }


    //xiaoli-decrypt
  bool result_xiaoli = cpabe.decrypt("xiaoliCP", outputStr, xiaoliStr);
  if (result_xiaoli && inputStr == xiaoliStr)
  {
    cout<<"xiaoli: decrypt success" <<endl;
    WriteBinaryFile(xiaoli_outputfile.c_str(), (uint8_t *)xiaoliStr.c_str(), xiaoliStr.size());
  }else{
    cout<<"xiaoli : decrypt failed" <<endl;
  }

  ShutdownOpenABE();
  cout << "cp-test end" << endl;

  return 0;
}

