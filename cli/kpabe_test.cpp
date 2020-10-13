// Author: dingbaozeng@bytedance.com
// Date: 2020.6.29

// currently KP-ABE demo only

#include "common.h"
#include "stdio.h"

using namespace std;
using namespace oabe;

void runSetup(OpenABE_SCHEME scheme_type, string &prefix, string &suffix, std::unique_ptr<OpenABEContextSchemeCCA> &schemeContext)
{
  try
  {
    OpenABEByteString mpkBlob, mskBlob;
    string mpkFile = MPK_ID + suffix, mskFile = MSK_ID + suffix;
    if (prefix != "")
    {
      mpkFile = prefix + mpkFile;
      mskFile = prefix + mskFile;
    }

    string mpkID = MPK_ID, mskID = MSK_ID;
    if (prefix != "")
    {
      mpkID = prefix + mpkID;
      mskID = prefix + mskID;
    }

    // Generate a set of parameters for an ABE authority
    if (schemeContext->generateParams(DEFAULT_PARAMETER_STRING, mpkID, mskID) != OpenABE_NOERROR)
    {
      cerr << "unable to generate parameters" << endl;
      return;
    }

    // don't password protect the master public parameters (not necessary here)
    if (schemeContext->exportKey(mpkID, mpkBlob) != OpenABE_NOERROR)
    {
      cerr << "unable to export public parameters" << endl;
      return;
    }

    if (schemeContext->exportKey(mskID, mskBlob) != OpenABE_NOERROR)
    {
      cerr << "unable to export master secret parameters" << endl;
      return;
    }

    cout << "writing mast public key into " << mpkFile << endl;
    WriteToFile(mpkFile.c_str(), MPK_BEGIN_HEADER + Base64Encode(mpkBlob.getInternalPtr(), mpkBlob.size()) + MPK_END_HEADER);

    cout << "writing master secret key into " << mskFile << endl;
    WriteToFile(mskFile.c_str(), MSK_BEGIN_HEADER + Base64Encode(mskBlob.getInternalPtr(), mskBlob.size()) + MSK_END_HEADER);
  }
  catch (OpenABE_ERROR &error)
  {
    cout << "caught exception: " << OpenABE_errorToString(error) << endl;
    return;
  }

  return;
}

void runAbeEncrypt(OpenABE_SCHEME scheme_type, string &prefix, string &suffix, string &func_input,
                   string &inputStr, string &ciphertextFile, std::unique_ptr<OpenABEContextSchemeCCA> &schemeContext)
{
  OpenABE_ERROR result = OpenABE_NOERROR;
  std::unique_ptr<OpenABEFunctionInput> funcInput = nullptr;
  string mpkID = MPK_ID;
  string mpkFile = MPK_ID + suffix;
  if (prefix != "")
  {
    mpkFile = prefix + mpkFile;
  }

  OpenABEByteString ct1Blob, ct2Blob, mpkBlob;

  try
  {
    // next, get the functional input for encryption (based on scheme type)
    if (scheme_type == OpenABE_SCHEME_KP_GPSW)
    {
      funcInput = createAttributeList(func_input);
    }
    else if (scheme_type == OpenABE_SCHEME_CP_WATERS)
    {
      funcInput = createPolicyTree(func_input);
    }
    ASSERT(funcInput != nullptr, OpenABE_ERROR_INVALID_INPUT);

    // for KP and CP, we only have to do this once
    mpkBlob = ReadFile(mpkFile.c_str());
    if (mpkBlob.size() == 0)
    {
      cerr << "master public parameters not encoded properly." << endl;
      return;
    }

    if ((result = schemeContext->loadMasterPublicParams(mpkID, mpkBlob)) != OpenABE_NOERROR)
    {
      cerr << "unable to load the master public parameters" << endl;
      throw result;
    }

    std::unique_ptr<OpenABECiphertext> ciphertext1(new OpenABECiphertext);
    std::unique_ptr<OpenABECiphertext> ciphertext2(new OpenABECiphertext);
    if ((result = schemeContext->encrypt(mpkID, funcInput.get(), inputStr, ciphertext1.get(), ciphertext2.get())) != OpenABE_NOERROR)
    {
      cerr << "error occurred during encryption" << endl;
      throw result;
    }

    // write to disk
    ciphertext1->exportToBytes(ct1Blob);
    ciphertext2->exportToBytesWithoutHeader(ct2Blob);
    string ctBlobStr = CT1_BEGIN_HEADER;
    ctBlobStr += NL + Base64Encode(ct1Blob.getInternalPtr(), ct1Blob.size()) + NL;
    ctBlobStr += CT1_END_HEADER;
    ctBlobStr += NL;
    ctBlobStr += CT2_BEGIN_HEADER;
    ctBlobStr += NL + Base64Encode(ct2Blob.getInternalPtr(), ct2Blob.size()) + NL;
    ctBlobStr += CT2_END_HEADER;
    ctBlobStr += NL;

    cout << "writing ciphertext into file " << ciphertextFile << endl;

    WriteToFile(ciphertextFile.c_str(), ctBlobStr);
  }
  catch (OpenABE_ERROR &error)
  {
    cout << "caught exception: " << OpenABE_errorToString(error) << endl;
  }

  return;
}

int runAbeKeygen(OpenABE_SCHEME scheme_type, string &prefix, string &suffix, string &keyInput, string &keyFile, string &userGlobID, std::unique_ptr<OpenABEContextSchemeCCA> &schemeContext)
{
  int err_code = -1;
  OpenABE_ERROR result = OpenABE_NOERROR;
  std::unique_ptr<OpenABEFunctionInput> funcInput = nullptr;
  OpenABEByteString mpkBlob, mskBlob, skBlob;

  string mpkID = MPK_ID, mskID = MSK_ID, skID = SK_ID, globSkID = userGlobID;
  string mpkFile = MPK_ID + suffix, mskFile = MSK_ID + suffix;
  if (prefix != "")
  {
    mpkFile = prefix + mpkFile;
    mskFile = prefix + mskFile;
  }

  try
  {
    // Get the functional input
    if (scheme_type == OpenABE_SCHEME_CP_WATERS)
    {
      funcInput = createAttributeList(keyInput);
    }
    else if (scheme_type == OpenABE_SCHEME_KP_GPSW)
    {
      funcInput = createPolicyTree(keyInput);
    }
    ASSERT(funcInput != nullptr, OpenABE_ERROR_INVALID_INPUT);

    // Do it once for CP or KP
    // read the file
    mpkBlob = ReadFile(mpkFile.c_str());
    if (mpkBlob.size() == 0)
    {
      cerr << "master public parameters not encoded correctly." << endl;
      return err_code;
    }

    mskBlob = ReadFile(mskFile.c_str());
    if (mskBlob.size() == 0)
    {
      cerr << "master secret parameters not encoded correctly." << endl;
      return err_code;
    }

    if ((result = schemeContext->loadMasterPublicParams(mpkID, mpkBlob)) != OpenABE_NOERROR)
    {
      cerr << "unable to load the master public parameters" << endl;
      throw result;
    }

    if ((result = schemeContext->loadMasterSecretParams(mskID, mskBlob)) != OpenABE_NOERROR)
    {
      cerr << "unable to load the master secret parameters" << endl;
      throw result;
    }
    // generate the user's key
    if ((result = schemeContext->keygen(funcInput.get(), skID, mpkID, mskID)) != OpenABE_NOERROR)
    {
      cout << "decryption key error" << endl;
      throw result;
    }

    // export the generated key
    if ((result = schemeContext->exportKey(skID, skBlob)) != OpenABE_NOERROR)
    {
      cout << "unable to export master secret parameters" << endl;
      throw result;
    }
    cout << "writing key into file " << keyFile << endl;
    WriteToFile(keyFile.c_str(), SK_BEGIN_HEADER + Base64Encode(skBlob.getInternalPtr(), skBlob.size()) + SK_END_HEADER);
    err_code = 0;
  }
  catch (OpenABE_ERROR &error)
  {
    cout << "caught exception: " << OpenABE_errorToString(error) << endl;
    err_code = error;
  }

  return err_code;
}

int runAbeDecrypt(OpenABE_SCHEME scheme_type, string &prefix, string &suffix,
                  string &skFile, string &ciphertextFile, string &outputFile, std::unique_ptr<OpenABEContextSchemeCCA> &schemeContext)
{
  OpenABE_ERROR result = OpenABE_NOERROR;
  std::unique_ptr<OpenABECiphertext> ciphertext1 = nullptr, ciphertext2 = nullptr;

  int err_code = 0;
  string mpkID = MPK_ID, skID = skFile;
  string mpkFile = MPK_ID + suffix;
  if (prefix != "")
  {
    mpkFile = prefix + mpkFile;
  }
  // read the file
  OpenABEByteString mpkBlob, skBlob, ct1Blob, ct2Blob;
  string plaintext;

  try
  {

    // load KP/CP public params
    mpkBlob = ReadFile(mpkFile.c_str());
    if (mpkBlob.size() == 0)
    {
      cerr << "master public parameters not encoded properly." << endl;
      return -1;
    }

    if ((result = schemeContext->loadMasterPublicParams(mpkID, mpkBlob)) != OpenABE_NOERROR)
    {
      cerr << "unable to load the master public parameters" << endl;
      throw result;
    }

    skBlob = ReadFile(skFile.c_str());
    if (skBlob.size() == 0)
    {
      cerr << "secret key not encoded properly." << endl;
      return -1;
    }

    ct1Blob = ReadBlockFromFile(CT1_BEGIN_HEADER, CT1_END_HEADER, ciphertextFile.c_str());
    if (ct1Blob.size() == 0)
    {
      cerr << "ABE ciphertext not encoded properly." << endl;
      return -1;
    }

    // Load the ciphertext components
    ciphertext1.reset(new OpenABECiphertext);
    ciphertext1->loadFromBytes(ct1Blob);

    ct2Blob = ReadBlockFromFile(CT2_BEGIN_HEADER, CT2_END_HEADER, ciphertextFile.c_str());
    if (ct2Blob.size() == 0)
    {
      cerr << "AEAD ciphertext not encoded properly." << endl;
    }
  }
  catch (OpenABE_ERROR &error)
  {
    cout << "caught exception: " << OpenABE_errorToString(error) << endl;
    err_code = error;
    return err_code;
  }

  try
  {
    // now we can load the user's secret key
    if ((result = schemeContext->loadUserSecretParams(skID, skBlob)) != OpenABE_NOERROR)
    {
      cerr << "Unable to load user's decryption key" << endl;
      throw result;
    }

    ciphertext2.reset(new OpenABECiphertext);
    ciphertext2->loadFromBytesWithoutHeader(ct2Blob);

    // now we can decrypt
    if ((result = schemeContext->decrypt(mpkID, skID, plaintext, ciphertext1.get(), ciphertext2.get())) != OpenABE_NOERROR)
    {
      throw result;
    }

    err_code = 0;

    cout << "writing palintext into file " << outputFile << endl;

    WriteBinaryFile(outputFile.c_str(), (uint8_t *)plaintext.c_str(), plaintext.size());
  }
  catch (OpenABE_ERROR &error)
  {
    cout << "caught exception: " << OpenABE_errorToString(error) << endl;
    err_code = error;
  }

  return err_code;
}

int readFile(string &input_file, string &inputStr)
{
  try
  {
    getFile(inputStr, input_file);
    size_t inputLen = inputStr.size();
    if (inputLen == 0 || inputLen > MAX_FILE_SIZE)
    {
      cerr << "input file is either empty or too big! Can encrypt up to 4GB files." << endl;
      return -1;
    }
  }
  catch (const std::ios_base::failure &e)
  {
    cerr << e.what() << endl;
    return -1;
  }
  return 0;
}

int test_kp(std::unique_ptr<OpenABEContextSchemeCCA> &schemeContext, OpenABE_SCHEME scheme, string &attr, string &policy,
            string &inputStr, string &ciphertextFile, string &keyOutfile, string &plaintext_file)
{

  ifstream f(plaintext_file.c_str());
  if (f.good())
  {
    remove(plaintext_file.c_str());
  }

  string prefix = "bytedance.", suffix = ".kpabe";
  cout << "\nencryption with attribution: " << attr << endl;
  runAbeEncrypt(scheme, prefix, suffix, attr, inputStr, ciphertextFile, schemeContext);
  string userGlobID = "";
  cout << "generate key with policy: " << policy << endl;
  runAbeKeygen(scheme, prefix, suffix, policy, keyOutfile, userGlobID, schemeContext);
  cout << "decrypt with key in file " << keyOutfile << endl;
  runAbeDecrypt(scheme, prefix, suffix, keyOutfile, ciphertextFile, plaintext_file, schemeContext);

  string plaintext = "";
  bool decrypted = false;
  if (readFile(plaintext_file, plaintext) == 0)
  {
    if (plaintext.compare(inputStr) == 0)
    {
      cout << "decrypt successfully!" << endl;
      decrypted = true;
    }
  }
  if (!decrypted)
  {
    cout << "decrypt failed!" << endl;
  }
  return 0;
}

int main()
{
  string prefix = "bytedance.", suffix = ".kpabe";
  string input_file = "input.txt";
  string inputStr = "";
  string ciphertext_file = "output.txt" + suffix;
  string keyOutfile = "analyst_kp.key";
  string plaintext_file = "plain.txt";
  string userGlobID = "";
  std::unique_ptr<OpenABEContextSchemeCCA> schemeContext = nullptr;

  InitializeOpenABE();
  OpenABE_SCHEME scheme = OpenABE_SCHEME_KP_GPSW;
  // Initialize a OpenABEContext structure
  schemeContext = OpenABE_createContextABESchemeCCA(scheme);
  if (schemeContext == nullptr)
  {
    cerr << "unable to create a new context" << endl;
    return 0;
  }
  cout << "setup kp-abe environment. " << endl;
  runSetup(scheme, prefix, suffix, schemeContext);

  // read the file content from input_file into inputStr
  readFile(input_file, inputStr);

  cout << "input file: " << input_file << endl;

  string attr = "App:Douyin|Level:high|IP:10.227.70.237|Date = June 28, 2020";

  // Test policy with `and`
  // should pass
  string policy = "(App:Douyin and (Date = June 1-30, 2020) and IP:10.227.70.237)";
  test_kp(schemeContext, scheme, attr, policy, inputStr, ciphertext_file, keyOutfile, plaintext_file);
  
  // should fail
  policy = "(App:TikTok and (Date = June 1-30, 2020) and IP:10.227.70.237)";
  test_kp(schemeContext, scheme, attr, policy, inputStr, ciphertext_file, keyOutfile, plaintext_file);

  // should fail
  policy = "(App:Douyin and (Date = June 1-30, 2020) and IP:10.227.70.118)";
  test_kp(schemeContext, scheme, attr, policy, inputStr, ciphertext_file, keyOutfile, plaintext_file);


  // Test policy with `or`
  // should pass
  policy = "((App:TikTok or App:Douyin) and(Date = June 1-30, 2020) and IP:10.227.70.237)";
  test_kp(schemeContext, scheme, attr, policy, inputStr, ciphertext_file, keyOutfile, plaintext_file);

  // should pass
  policy = "(App:Douyin and (Date = June 1-30, 2020) or IP:10.227.70.118)";
  test_kp(schemeContext, scheme, attr, policy, inputStr, ciphertext_file, keyOutfile, plaintext_file);

  // Test policy with ">, < "
  // should pass
  policy = "(App:Douyin and (Date > June 1, 2020) and IP:10.227.70.237)";
  test_kp(schemeContext, scheme, attr, policy, inputStr, ciphertext_file, keyOutfile, plaintext_file);
  // should pass
  policy = "(App:Douyin and (Date < July 1, 2020) and IP:10.227.70.237)";
  test_kp(schemeContext, scheme, attr, policy, inputStr, ciphertext_file, keyOutfile, plaintext_file);
  
  // should fail
  policy = "(App:Douyin and (Date > July 1, 2020) and IP:10.227.70.237)";
  test_kp(schemeContext, scheme, attr, policy, inputStr, ciphertext_file, keyOutfile, plaintext_file);
  
  
  ShutdownOpenABE();
}

