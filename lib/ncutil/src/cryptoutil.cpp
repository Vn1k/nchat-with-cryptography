// cryptoutil.cpp
//
// Copyright (c) 2025 Kristofer Berggren
// All rights reserved.
//
// nchat is distributed under the MIT license, see LICENSE for details.

#include "cryptoutil.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <sys/stat.h>

#include <vector>

#include "fileutil.h"
#include "log.h"
#include "strutil.h"

namespace
{
  constexpr size_t KEY_SIZE = 32; // AES-256
  constexpr size_t IV_SIZE = 12;  // recommended size for GCM
  constexpr size_t TAG_SIZE = 16;
}

std::string CryptoUtil::m_KeyPath;
std::vector<unsigned char> CryptoUtil::m_Key;
bool CryptoUtil::m_KeyLoaded = false;
std::mutex CryptoUtil::m_KeyMutex;

void CryptoUtil::Init(const std::string& p_KeyPath)
{
  std::lock_guard<std::mutex> lock(m_KeyMutex);
  m_KeyPath = p_KeyPath;
  m_Key.clear();
  m_KeyLoaded = false;
}

bool CryptoUtil::IsReady()
{
  return EnsureKey();
}

bool CryptoUtil::Encrypt(const std::string& p_PlainText, std::string& p_HexCipherText)
{
  if (p_PlainText.empty())
  {
    p_HexCipherText.clear();
    return true;
  }

  if (!EnsureKey()) return false;

  std::vector<unsigned char> key;
  {
    std::lock_guard<std::mutex> lock(m_KeyMutex);
    key = m_Key;
  }

  std::vector<unsigned char> iv(IV_SIZE);
  if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1)
  {
    LOG_WARNING("failed to generate encryption iv");
    return false;
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr)
  {
    LOG_WARNING("failed to allocate cipher context");
    return false;
  }

  bool success = true;
  int len = 0;
  std::vector<unsigned char> cipherText(p_PlainText.size());
  int cipherLen = 0;

  if (success && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
  {
    success = false;
  }

  if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1)
  {
    success = false;
  }

  if (success && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
  {
    success = false;
  }

  if (success &&
      EVP_EncryptUpdate(ctx, cipherText.data(), &len,
                        reinterpret_cast<const unsigned char*>(p_PlainText.data()),
                        static_cast<int>(p_PlainText.size())) != 1)
  {
    success = false;
  }

  cipherLen = len;

  if (success && EVP_EncryptFinal_ex(ctx, cipherText.data() + len, &len) != 1)
  {
    success = false;
  }

  cipherLen += len;
  cipherText.resize(cipherLen);

  unsigned char tag[TAG_SIZE] = { 0 };
  if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1)
  {
    success = false;
  }

  EVP_CIPHER_CTX_free(ctx);

  if (!success)
  {
    LOG_WARNING("failed to encrypt data");
    return false;
  }

  std::string combined;
  combined.reserve(iv.size() + TAG_SIZE + cipherText.size());
  combined.append(reinterpret_cast<const char*>(iv.data()), iv.size());
  combined.append(reinterpret_cast<const char*>(tag), TAG_SIZE);
  combined.append(reinterpret_cast<const char*>(cipherText.data()), cipherText.size());

  p_HexCipherText = StrUtil::StrToHex(combined);
  return true;
}

bool CryptoUtil::Decrypt(const std::string& p_HexCipherText, std::string& p_PlainText)
{
  if (p_HexCipherText.empty())
  {
    p_PlainText.clear();
    return true;
  }

  if (!EnsureKey()) return false;

  std::vector<unsigned char> key;
  {
    std::lock_guard<std::mutex> lock(m_KeyMutex);
    key = m_Key;
  }

  const std::string combined = StrUtil::StrFromHex(p_HexCipherText);
  if (combined.size() < (IV_SIZE + TAG_SIZE))
  {
    LOG_WARNING("ciphertext too small");
    return false;
  }

  const unsigned char* data = reinterpret_cast<const unsigned char*>(combined.data());
  std::vector<unsigned char> iv(data, data + IV_SIZE);
  std::vector<unsigned char> tag(data + IV_SIZE, data + IV_SIZE + TAG_SIZE);
  std::vector<unsigned char> cipherText(data + IV_SIZE + TAG_SIZE, data + combined.size());

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr)
  {
    LOG_WARNING("failed to allocate cipher context");
    return false;
  }

  bool success = true;
  int len = 0;
  std::vector<unsigned char> plain(cipherText.size());
  int plainLen = 0;

  if (success && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
  {
    success = false;
  }

  if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1)
  {
    success = false;
  }

  if (success && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
  {
    success = false;
  }

  if (success &&
      EVP_DecryptUpdate(ctx, plain.data(), &len, cipherText.data(), static_cast<int>(cipherText.size())) != 1)
  {
    success = false;
  }

  plainLen = len;

  if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1)
  {
    success = false;
  }

  if (success && EVP_DecryptFinal_ex(ctx, plain.data() + len, &len) != 1)
  {
    success = false;
  }

  plainLen += len;
  plain.resize(plainLen);
  
  EVP_CIPHER_CTX_free(ctx);

  if (!success)
  {
    LOG_WARNING("failed to decrypt data");
    return false;
  }

  p_PlainText.assign(reinterpret_cast<const char*>(plain.data()), plain.size());
  return true;
}

bool CryptoUtil::EnsureKey()
{
  std::lock_guard<std::mutex> lock(m_KeyMutex);
  if (m_KeyLoaded) return true;
  m_KeyLoaded = LoadKeyLocked();
  return m_KeyLoaded;
}

bool CryptoUtil::LoadKeyLocked()
{
  if (m_KeyPath.empty())
  {
    LOG_WARNING("encryption key path not set");
    return false;
  }

  if (FileUtil::Exists(m_KeyPath))
  {
    std::string keyHex = FileUtil::ReadFile(m_KeyPath);
    StrUtil::Trim(keyHex);
    std::string keyRaw = StrUtil::StrFromHex(keyHex);
    if (keyRaw.size() == KEY_SIZE)
    {
      m_Key.assign(keyRaw.begin(), keyRaw.end());
      return true;
    }

    LOG_WARNING("invalid encryption key, regenerating");
  }

  std::vector<unsigned char> key(KEY_SIZE);
  if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1)
  {
    LOG_WARNING("failed to generate encryption key");
    return false;
  }

  std::string keyRaw(reinterpret_cast<const char*>(key.data()), key.size());
  std::string keyHex = StrUtil::StrToHex(keyRaw);
  FileUtil::WriteFile(m_KeyPath, keyHex + "\n");
  chmod(m_KeyPath.c_str(), 0600);

  m_Key = key;
  return true;
}
