#include <openssl/evp.h>
#include <openssl/rand.h>

#include <fstream>
#include <iostream>
#include <vector>
#include <stdio.h>
#include <string.h>
#include "base64/base64.h"
#define PASS_WORD "12345678"
void handleErrors() {
  std::cerr << "An error occurred" << std::endl;
  exit(1);
}

// 加密函数
std::vector<unsigned char> encrypt(const std::string& plaintext, const std::vector<unsigned char>& key,
                                   std::vector<unsigned char>& iv) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) handleErrors();

  std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
  int len;
  int ciphertext_len;

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) handleErrors();

  if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                        plaintext.size()) != 1)
    handleErrors();
  ciphertext_len = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) handleErrors();
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  ciphertext.resize(ciphertext_len);
  return ciphertext;
}

// 解密函数
std::string decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key,
                    const std::vector<unsigned char>& iv) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) handleErrors();
  int len;
  int plaintext_len;

  std::vector<unsigned char> plaintext(ciphertext.size());

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) handleErrors();
  if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) handleErrors();
  plaintext_len = len;
  if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  plaintext.resize(plaintext_len);
  return std::string(plaintext.begin(), plaintext.end());
}
void parseCmd(char* in) {}
int main(int argc, char* argv[]) {
  std::string file_name;
  std::string pass_word;
  std::string strings;
  std::string help_str="  -p password,get from minos ,usage: -p xxx \r\n \
  -f Decrypt the file, followed by the decrypted file. usage: -f xxx\r\n \
  -i Decrypt string followed by decrypted string, usage: -i xxx \r\n";
  int index = 1;
  bool getline_flag = false;
  if (argc >= 2) {
    while (argc > index) {
      if (0 == strcmp(argv[index], "-p")) {
        index++;
        if (argc > index) {
          pass_word = argv[index];
          index++;
        } else {
          std::cout << "lack param -p" << std::endl;
          return -1;
        }

      } else if (0 == strcmp(argv[index], "-f")) {
        index++;
        if (argc > index) {
          file_name = argv[index];
          index++;
        } else {
          std::cout << "lack param -f" << std::endl;
          return -1;
        }
      } else if (0 == strcmp(argv[index], "-i")) {
        index++;
        if (argc > index) {
          strings = argv[index];
          index++;
        } else {
          std::cout << "lack param -i" << std::endl;
          return -1;
        }
      } else if (0 == strcmp(argv[index], "-h")) {
        index++;
        std::cout<<help_str<<std::endl;
        return 0;
      } else if(0 == strcmp(argv[index], "-o")){
        index++;
        getline_flag = true;
      }
    }
  } else {
    std::cout << "need input a file" << std::endl;
    return -1;
  }
  if (pass_word.size() == 0) {
    std::cout << "PASS WORD ERROR" << std::endl;
    return -1;
  }

  
  // if(file_name.size() == 0 && strings.size() == 0) {
  //   std::cout << "need content" << std::endl;
  //   return -1;
  // }
  if(file_name.size() != 0 && strings.size() != 0) {
    std::cout << "too many param" << std::endl;
    return -1;
  }
  // 生成密钥和IV
  std::vector<unsigned char> key(32);  // AES-256
  std::vector<unsigned char> iv(EVP_MAX_IV_LENGTH);
  std::string key_val = "0123456789abcdef0123456789abcdef";  // 16 bytes for AES-128
  std::string iv_val = "1234567890abcdef";   // 16 bytes for AES-128
  key.assign(key_val.begin(), key_val.end());
  std::copy(pass_word.begin(), pass_word.end(), key.begin());
  iv.assign(iv_val.begin(), iv_val.end());
  // std::copy(pass_word.begin(), pass_word.end(), iv.begin());
  // std::cout << "Byte Vector: ";
  // for (unsigned char byte : key) {
  //     std::cout  << byte << " ";
  // }
  // std::cout <<std::endl;
  if(file_name.size() != 0) {
    // 从文件中读取
    std::ifstream infile(file_name.data(), std::ios::binary);
    int index = 0;
    infile.seekg(0, std::ios::end);
    int end = infile.tellg();
    infile.seekg(0, std::ios::beg);

    // index += read_iv.size();
    // infile.seekg(index, std::ios::beg);
    int get_len = 0;
    std::vector<unsigned char> read_encrypted_log;
    std::string read_data;
    std::string decode_data;
    // std::cout << "end: " << end << std::endl;

    std::ofstream ofile;
    ofile.open(file_name + ".out", std::ios::trunc);
    while (infile.tellg() < end) {
      // std::cout << "index1: " << infile.tellg() << std::endl;
      std::string byteString(5, '\0');
      infile.read(const_cast<char*>(byteString.data()), 4);
      get_len = std::stoi(byteString);
      // std::cout << "index2: " << infile.tellg() << " len:" << get_len << std::endl;

      read_data.resize(get_len);
      infile.read(const_cast<char*>(read_data.data()), get_len);

      decode_data = base64_decode(read_data);
      // std::cout << "decode size: " << decode_data.size() << std::endl;
      read_encrypted_log.resize(decode_data.size());
      read_encrypted_log.assign(decode_data.begin(), decode_data.end());
      // std::cout << "read_encrypted_log size: " << read_encrypted_log.size() << std::endl;

      std::string decrypted_log = decrypt(read_encrypted_log, key, iv);
      ofile << decrypted_log;
      // std::cout << "Decrypted log: " << decrypted_log << std::endl;
    }

    infile.close();
  }

  if(strings.size() != 0){
    int str_index = 0;
    std::vector<unsigned char> read_encrypted_log;
    std::string read_data;
    std::string decode_data;
    int str_len = strings.size();
    while(str_len > str_index){
      int get_len = 0;
      std::string byteString = strings.substr(str_index, 4);
      str_index += 4;
      byteString.push_back('\0');
      get_len = std::stoi(byteString);
      // std::cout << "len:" << get_len << std::endl;
      read_data = strings.substr(str_index, get_len);
      str_index += get_len;
      decode_data = base64_decode(read_data);
      // std::cout << "decode size: " << decode_data.size() << std::endl;
      read_encrypted_log.resize(decode_data.size());
      read_encrypted_log.assign(decode_data.begin(), decode_data.end());
      // std::cout << "read_encrypted_log size: " << read_encrypted_log.size() << std::endl;

      std::string decrypted_log = decrypt(read_encrypted_log, key, iv);
      std::cout << decrypted_log;
    }
  }



  if (true == getline_flag) {
    std::string line(4096, '\0');
    std::string byteString;
    std::string read_data;
    std::string decode_data;
    std::vector<unsigned char> read_encrypted_log;
    char c;
    int size_index = 0;
    while (true) {
      c = std::cin.get();
      if(c <= '9' && c >='0'){
        byteString.push_back(c);
        size_index++;
        if(size_index> 4){
          byteString.clear();
          size_index = 0;
        }
      }else {
        if(byteString.size() == 4){
          int get_len = 0;
          byteString.push_back('\0');
          get_len = std::stoi(byteString);
          // std::cout<<"get_len:"<<get_len<<std::endl;
          byteString.clear();
          size_index = 0;
          while(true) {
            
            size_index++;
            read_data.push_back(c);
            if(size_index >= get_len) {
              // std::cout<<"read_data size:"<<read_data.size()<<std::endl;
              // std::cout<<"read_data :"<<read_data<<std::endl;
              decode_data = base64_decode(read_data);
              // std::cout << "decode size: " << decode_data.size() << std::endl;
              read_encrypted_log.resize(decode_data.size());
              read_encrypted_log.assign(decode_data.begin(), decode_data.end());
              // std::cout << "read_encrypted_log size: " << read_encrypted_log.size() << std::endl;

              std::string decrypted_log = decrypt(read_encrypted_log, key, iv);
              std::cout << decrypted_log;
              size_index = 0;
              read_data.clear();
              break;
            }
            c = std::cin.get();
          }
        }else{
          byteString.clear();
          size_index = 0;
        }
      }

      // std::streamsize bytesRead = std::cin.gcount();
      // if (bytesRead != 0) {
      //   int str_index = 0;
      //   std::vector<unsigned char> read_encrypted_log;
      //   std::string read_data;
      //   std::string decode_data;
      //   int str_len = bytesRead;
      //   while (str_len > str_index) {
      //     int get_len = 0;
      //     std::string byteString = line.substr(str_index, 4);
      //     str_index += 4;
      //     byteString.push_back('\0');
      //     get_len = std::stoi(byteString);
      //      std::cout << "len:" << get_len << std::endl;
      //     read_data = line.substr(str_index, get_len);
      //     str_index += get_len;
      //     decode_data = base64_decode(read_data);
      //      std::cout << "decode size: " << decode_data.size() << std::endl;
      //     read_encrypted_log.resize(decode_data.size());
      //     read_encrypted_log.assign(decode_data.begin(), decode_data.end());
      //      std::cout << "read_encrypted_log size: " << read_encrypted_log.size() << std::endl;

      //     std::string decrypted_log = decrypt(read_encrypted_log, key, iv);
      //     std::cout << decrypted_log;
      //   }
      // }
    }
  }
  return 0;
}
