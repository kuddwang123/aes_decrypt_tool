#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#include <boost/filesystem.hpp>
#include <fstream>
#include <iostream>
#include <vector>

#include "base64.h"
#include "log.h"
#define MILD

std::vector<unsigned char> key(32);  // AES-256
std::vector<unsigned char> iv(EVP_MAX_IV_LENGTH);

void handleErrors() {
  std::cerr << "An error occurred" << std::endl;
  exit(1);
}
// void handleErrors() {
//   std::cerr << "An error occurred" << std::endl;
//   exit(1);
// }

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
bool decryptMild(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& iv, std::string& out) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return false;
  }
  int len;
  int plaintext_len;

  std::vector<unsigned char> plaintext(ciphertext.size());

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
    return false;
  }
  if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
    return false;
  }
  plaintext_len = len;
  if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
    return false;
  }
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  plaintext.resize(plaintext_len);
  out.append(plaintext.begin(), plaintext.end());
  return true;
}

void traverseDirectory(const std::string& dirPath, std::vector<std::string>* out) {
  for (const auto& entry : boost::filesystem::directory_iterator(dirPath)) {
    if (boost::filesystem::is_regular_file(entry)) {
      out->emplace_back(entry.path().string());
      std::cout << "File: " << entry.path().string() << std::endl;
    } else if (boost::filesystem::is_directory(entry)) {
      std::cout << "Directory: " << entry.path().string() << std::endl;
      traverseDirectory(entry.path().string(), out);  // 递归遍历子目录
    }
  }
}
void decryptFile(const std::string& file_name) {
  // 从文件中读取
  std::ifstream infile(file_name.data(), std::ios::binary);
  int index_len = 0;
  infile.seekg(0, std::ios::end);
  int end = infile.tellg();
  infile.seekg(0, std::ios::beg);

  int get_len = 0;
  bool normal_log = true;
  std::vector<unsigned char> read_encrypted_log;
  std::string read_data;
  std::string decode_data;
  std::string out_file_name = "./out/" + file_name + ".out";
  std::ofstream ofile;
  std::string temp_need_decrypt_str;
  // 创建目录
  boost::filesystem::path dir_path = boost::filesystem::path(out_file_name).parent_path();
  if (!boost::filesystem::exists(dir_path)) {
    boost::filesystem::create_directories(dir_path);
  }
  // 创建文件

  ofile.open(out_file_name, std::ios::trunc);
  while (infile.tellg() < end && (infile.tellg() != -1)) {
    // LOG("index1: %d\r\n", static_cast<int>(infile.tellg()));
    static std::string byteString(5, '\0');
    std::string line;
    infile.read(const_cast<char*>(byteString.data() + index_len), 1);
    if (normal_log == true) {
      if ((byteString.at(index_len) > '9' || (byteString.at(index_len)) < '0') && byteString.at(index_len) != '\0') {
        // std::cout<<"here infile.tellg()="<<infile.tellg()<<std::endl;
        std::getline(infile, line);
        ofile << byteString.at(index_len);
        ofile << line << std::endl;
        LOG("getline: %d\r\n", static_cast<int>(infile.tellg()));
        index_len = 0;
        continue;
      }
      if (byteString.at(index_len) == '\0') {
        // static int i_flag = 0;
        // std::cout << "geterr: " <<i_flag<<" ednd = "<<end<<" infile.tellg()="<<infile.tellg()<<std::endl;
        // i_flag++;
        // while(infile.tellg() == -1);
        index_len = 0;
        continue;
      }
    } else {
      if ((byteString.at(index_len) > '9' || (byteString.at(index_len)) < '0')) {
        // std::cout << "error code:" << (int)(byteString.at(index_len)) << std::endl;
        index_len = 0;
        continue;
      }
    }

    index_len++;
    if (index_len < 4) {
      continue;
    }
    index_len = 0;
    normal_log = false;
    // LOG("Byte Vector: \r\n");
    // // std::cout << "Byte Vector: ";
    // for (int i =0; i < 4; i++) {
    //   LOG("%d\r\n",(int)(byteString.at(i)));
    // }
    // std::cout << std::endl;
    get_len = std::stoi(byteString);
    //  std::cout << "index2: " << infile.tellg() << " len:" << get_len << std::endl;
    if(get_len % 4 != 0) {
      std::cout << "get len fail size: " <<  get_len << std::endl;
      continue;
    }
    LOG("get_len : %d\r\n", get_len);
    read_data.resize(get_len);
    infile.read(const_cast<char*>(read_data.data()), get_len);
    LOG("read_data : %s, infile.tellg()=%d\r\n", read_data.c_str(), static_cast<int>(infile.tellg()));
    size_t position = read_data.find('=');
    if ((position != std::string::npos) && (position + 3 <= read_data.size())) {
        int temp_index = 0;
        // std::cout << "get = index: " << position << std::endl;
        while (1) {
          temp_index++;
          if (read_data.at(position + temp_index) != '=') {
            break;
          } else {
            std::cout << "get = at index: " << position + temp_index << std::endl;
          }
        }
        temp_need_decrypt_str.append(read_data.begin()+ position + temp_index, read_data.end());
        LOG("temp_need_decrypt_str: %s\r\n", temp_need_decrypt_str.c_str());
        int back_len = get_len - position - temp_index;
        if(infile.tellg() != -1){
          infile.seekg(infile.tellg() - back_len, std::ios::beg);
        }
        continue;
    }
    bool ret = false;
    decode_data = base64_decode(read_data, ret);
    if(ret == false) {
      std::cout << "in base64_decode fail" << std::endl;
      continue;
    }
    LOG("decode size: %ld\r\n", decode_data.size());
    read_encrypted_log.resize(decode_data.size());
    read_encrypted_log.assign(decode_data.begin(), decode_data.end());
    LOG("read_encrypted_log size: %ld\r\n", read_encrypted_log.size());
#ifdef MILD
    std::string decrypted_log;
    bool flag = decryptMild(read_encrypted_log, key, iv, decrypted_log);
    if (flag == false) {
      std::cout << "read_data " << read_data<<std::endl;
      std::cout << "in decryptMild fail" << std::endl;
      continue;
    }
#else
    std::string decrypted_log = decrypt(read_encrypted_log, key, iv);
#endif
    ofile << decrypted_log;
    LOG("Decrypted log:  %s\r\n", decrypted_log.c_str());
  }
  // LOG("Decrypted log:  %s\r\n", decrypted_log.c_str());
  std::cout << " end = " << end << " actual=" << infile.tellg() << std::endl;
  infile.close();
}

void parseCmd(char* in) {}
int main(int argc, char* argv[]) {
  std::string file_name;
  std::string pass_word;
  std::string strings;
  std::string directory_target;
  std::string help_str =
      "  -p password,get from minos ,usage: -p xxx \r\n \
  -f Decrypt the file, followed by the decrypted file. usage: -f xxx\r\n \
  -d Decrypt the directory, followed by the decrypted direcotry. usage: -d xxx\r\n \
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
        std::cout << help_str << std::endl;
        return 0;
      } else if (0 == strcmp(argv[index], "-o")) {
        index++;
        getline_flag = true;
      } else if (0 == strcmp(argv[index], "-d")) {
        index++;
        if (argc > index) {
          directory_target = argv[index];
          index++;
        } else {
          std::cout << "lack param -d" << std::endl;
          return -1;
        }
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

  if (file_name.size() != 0 && strings.size() != 0) {
    std::cout << "too many param" << std::endl;
    return -1;
  }

  std::string key_val = "0123456789abcdef0123456789abcdef";  // 16 bytes for AES-128
  std::string iv_val = "1234567890abcdef";                   // 16 bytes for AES-128
  key.assign(key_val.begin(), key_val.end());
  std::copy(pass_word.begin(), pass_word.end(), key.begin());
  iv.assign(iv_val.begin(), iv_val.end());
  // std::copy(pass_word.begin(), pass_word.end(), iv.begin());
  // std::cout << "Byte Vector: ";
  // for (unsigned char byte : key) {
  //     std::cout  << byte << " ";
  // }
  // std::cout <<std::endl;
  if (file_name.size() != 0) {
    decryptFile(file_name);
  }

  if (strings.size() != 0) {
    int str_index = 0;
    std::vector<unsigned char> read_encrypted_log;
    std::string read_data;
    std::string decode_data;
    int str_len = strings.size();
    while (str_len > str_index) {
      int get_len = 0;
      std::string byteString = strings.substr(str_index, 4);
      str_index += 4;
      byteString.push_back('\0');
      get_len = std::stoi(byteString);
      // std::cout << "len:" << get_len << std::endl;
      read_data = strings.substr(str_index, get_len);
      str_index += get_len;
      bool ret = false;
      decode_data = base64_decode(read_data, ret);
      if(ret == false) {
        std::cout << "in base64_decode fail" << std::endl;
        return 0;
      }
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
    std::string temp_need_decrypt_str;
    char c;
    int size_index = 0;
    int temp_need_decrypt_str_index = 0;
    while (true) {
      if(temp_need_decrypt_str.size() == 0){
        // std::cout << "will here " << std::endl;
        c = std::cin.get();
      } else {
 //       std::cout << "temp_need_decrypt_str size : "  << temp_need_decrypt_str.size()<<" temp_need_decrypt_str_index:"<<temp_need_decrypt_str_index<<std::endl;
        c = temp_need_decrypt_str.at(temp_need_decrypt_str_index);
        // std::cout << "c: " <<  c << std::endl;
        temp_need_decrypt_str_index++;
        if(temp_need_decrypt_str.size() <= temp_need_decrypt_str_index){
          temp_need_decrypt_str.clear();
          std::cout << "temp_need_decrypt_str size: " <<  temp_need_decrypt_str.size() << std::endl;
          temp_need_decrypt_str_index = 0;
        }
      }

      if (c <= '9' && c >= '0') {
        byteString.push_back(c);
        size_index++;
        if (size_index > 4) {
          byteString.clear();
          size_index = 0;
        }
      } 
        if (byteString.size() == 4) {
          int get_len = 0;
          byteString.push_back('\0');
          get_len = std::stoi(byteString);
          if(get_len %4 != 0) {
            std::cout << "get len fail2 size: " <<  get_len << std::endl;
            byteString.clear();
            size_index = 0;
            continue;
          }
          //  std::cout<<"get_len:"<<get_len<<std::endl;
          byteString.clear();
          size_index = 0;
          while (true) {
            if(temp_need_decrypt_str.size() == 0){
              c = std::cin.get();
            } else {
              c = temp_need_decrypt_str.at(temp_need_decrypt_str_index);
              temp_need_decrypt_str_index++;
              if(temp_need_decrypt_str.size() <= temp_need_decrypt_str_index){
                temp_need_decrypt_str.clear();
                temp_need_decrypt_str_index = 0;
              }
            }
            size_index++;
            read_data.push_back(c);
            if (size_index >= get_len) {
              ///////////////////////////
              size_t position = read_data.find('=');
              if ((position != std::string::npos) && (position + 3 <= read_data.size())) {
                  int temp_index = 0;
                  // std::cout << "get = index: " << position << std::endl;
                  while (1) {
                    temp_index++;
                    if (read_data.at(position + temp_index) != '=') {
                      break;
                    } else {
                      std::cout << "get = at index: " << position + temp_index << std::endl;
                    }
                  }
                  temp_need_decrypt_str.append(read_data.begin()+ position + temp_index, read_data.end());
                   LOG("temp_need_decrypt_str: %s\r\n", temp_need_decrypt_str.c_str());
                  // int back_len = get_len - position - temp_index;
                  // if(infile.tellg() != -1){
                  //   infile.seekg(infile.tellg() - back_len, std::ios::beg);
                  // }
                  size_index = 0;
                  read_data.clear();
                  break;
              }
              // std::cout<<"read_data size:"<<read_data.size()<<std::endl;
              //  std::cout<<"read_data :"<<read_data<<std::endl;
              bool ret = false;
              decode_data = base64_decode(read_data, ret);
              if(ret == false) {
                std::cout << "in base64_decode fail" << std::endl;
                size_index = 0;
                read_data.clear();
                break;
              }
              //  std::cout << "decode size: " << decode_data.size() << std::endl;
              read_encrypted_log.resize(decode_data.size());
              read_encrypted_log.assign(decode_data.begin(), decode_data.end());
              //  std::cout << "read_encrypted_log size: " << read_encrypted_log.size() << std::endl;

              #ifdef MILD
                  std::string decrypted_log;
                  bool flag = decryptMild(read_encrypted_log, key, iv, decrypted_log);
                  if (flag == false) {
                    std::cout << "in decryptMild fail" << std::endl;
                    size_index = 0;
                    read_data.clear();
                    continue;
                  }
              #else
                  std::string decrypted_log = decrypt(read_encrypted_log, key, iv);
              #endif
              std::cout << decrypted_log;
              size_index = 0;
              read_data.clear();
              break;
            }
            
          }
        }
    }
  }

  if (directory_target.size() != 0) {
    std::vector<std::string> files;
    traverseDirectory(directory_target, &files);
    for (auto file : files) {
      decryptFile(file);
    }
  }
  return 0;
}
