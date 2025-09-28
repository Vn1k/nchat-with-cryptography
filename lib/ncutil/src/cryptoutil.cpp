// cryptoutil.cpp
//
// Copyright (c) 2025 Kristofer Berggren
// All rights reserved.
//
// nchat is distributed under the MIT license, see LICENSE for details.

#include "cryptoutil.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <sys/stat.h>

#include <cstdlib>
#include <sstream>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#endif

#include "fileutil.h"
#include "log.h"
#include "strutil.h"

namespace
{
  constexpr size_t KEY_SIZE = 32; // AES-256
  constexpr size_t IV_SIZE = 12;  // recommended size for GCM
  constexpr size_t TAG_SIZE = 16;
  constexpr size_t SALT_SIZE = 16;
  constexpr int PBKDF2_ITERATIONS = 200000;
  const char* const PASSPHRASE_ENV = "NCHAT_KEY_PASSPHRASE";
  const char* const KEYFILE_MAGIC = "format=enc-v1";
}

std::string CryptoUtil::m_KeyPath;
std::vector<unsigned char> CryptoUtil::m_Key;
bool CryptoUtil::m_KeyLoaded = false;
std::mutex CryptoUtil::m_KeyMutex;
bool CryptoUtil::m_UsePassphrase = false;
std::string CryptoUtil::m_Passphrase;
bool CryptoUtil::m_KeyLocked = false;

void CryptoUtil::Init(const std::string& p_KeyPath)
{
  std::lock_guard<std::mutex> lock(m_KeyMutex);
  m_KeyPath = p_KeyPath;
  ClearKeyLocked();
  m_KeyLoaded = false;

  StrUtil::SecureZero(m_Passphrase);
  const char* passphraseEnv = getenv(PASSPHRASE_ENV);
  if ((passphraseEnv != nullptr) && (passphraseEnv[0] != '\0'))
  {
    m_Passphrase = std::string(passphraseEnv);
    m_UsePassphrase = true;
  }
  else
  {
    m_Passphrase.clear();
    m_UsePassphrase = false;
  }

#if defined(_WIN32)
  _putenv_s(PASSPHRASE_ENV, "");
#else
  unsetenv(PASSPHRASE_ENV);
#endif
}

void CryptoUtil::SetPassphrase(const std::string& p_Passphrase)
{
  std::lock_guard<std::mutex> lock(m_KeyMutex);
  StrUtil::SecureZero(m_Passphrase);
  m_Passphrase = p_Passphrase;
  m_UsePassphrase = !m_Passphrase.empty();
  m_KeyLoaded = false;
  ClearKeyLocked();
}

bool CryptoUtil::IsPassphraseProtected()
{
  std::lock_guard<std::mutex> lock(m_KeyMutex);
  if (m_KeyPath.empty() || !FileUtil::Exists(m_KeyPath)) return false;

  std::string keyData = FileUtil::ReadFile(m_KeyPath);
  StrUtil::Trim(keyData);
  return StrUtil::StartsWith(keyData, KEYFILE_MAGIC);
}

bool CryptoUtil::ChangePassphrase(const std::string& p_OldPassphrase,
                                  const std::string& p_NewPassphrase)
{
  std::lock_guard<std::mutex> lock(m_KeyMutex);
  if (m_KeyPath.empty())
  {
    LOG_WARNING("encryption key path not set");
    return false;
  }

  std::string prevPassphrase = m_Passphrase;
  const bool prevUsePassphrase = m_UsePassphrase;
  const bool prevKeyLoaded = m_KeyLoaded;
  std::vector<unsigned char> prevKey = m_Key;

  StrUtil::SecureZero(m_Passphrase);
  m_Passphrase = p_OldPassphrase;
  m_UsePassphrase = !m_Passphrase.empty();
  ClearKeyLocked();
  m_KeyLoaded = false;

  if (!LoadKeyLocked())
  {
    LOG_WARNING("failed to unlock cache key with provided passphrase");
    StrUtil::SecureZero(m_Passphrase);
    m_Passphrase = prevPassphrase;
    m_UsePassphrase = prevUsePassphrase;
    ClearKeyLocked();
    m_Key = prevKey;
    LockKeyMemory();
    m_KeyLoaded = prevKeyLoaded;
    StrUtil::SecureZero(prevPassphrase);
    SecureZero(prevKey);
    return false;
  }

  m_KeyLoaded = true;
  std::vector<unsigned char> keyPlain = m_Key;

  StrUtil::SecureZero(m_Passphrase);
  m_Passphrase = p_NewPassphrase;
  m_UsePassphrase = !m_Passphrase.empty();

  if (!PersistKeyLocked(keyPlain))
  {
    LOG_WARNING("failed to persist cache key with new passphrase");
    StrUtil::SecureZero(m_Passphrase);
    m_Passphrase = p_OldPassphrase;
    m_UsePassphrase = !m_Passphrase.empty();
    if (!PersistKeyLocked(keyPlain))
    {
      LOG_WARNING("failed to restore original cache key protection");
    }
    StrUtil::SecureZero(m_Passphrase);
    m_Passphrase = prevPassphrase;
    m_UsePassphrase = prevUsePassphrase;
    ClearKeyLocked();
    m_Key = prevKey;
    LockKeyMemory();
    m_KeyLoaded = prevKeyLoaded;
    SecureZero(keyPlain);
    StrUtil::SecureZero(prevPassphrase);
    SecureZero(prevKey);
    return false;
  }

  ClearKeyLocked();
  m_Key = keyPlain;
  LockKeyMemory();
  m_KeyLoaded = true;

  SecureZero(keyPlain);
  StrUtil::SecureZero(prevPassphrase);
  SecureZero(prevKey);
  return true;
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
    std::string keyData = FileUtil::ReadFile(m_KeyPath);
    StrUtil::Trim(keyData);

    std::vector<unsigned char> keyCandidate;
    const bool isEncrypted = StrUtil::StartsWith(keyData, KEYFILE_MAGIC);

    if (isEncrypted)
    {
      if (!m_UsePassphrase)
      {
        LOG_WARNING("encryption key is passphrase protected but no passphrase provided (set %s)", PASSPHRASE_ENV);
        return false;
      }

      if (!DecryptStoredKey(keyData, keyCandidate))
      {
        LOG_WARNING("failed to decrypt stored encryption key");
        SecureZero(keyCandidate);
        return false;
      }

      ClearKeyLocked();
      m_Key = keyCandidate;
      LockKeyMemory();
      SecureZero(keyCandidate);
      return true;
    }
    else
    {
      std::string keyRaw = StrUtil::StrFromHex(keyData);
      if (keyRaw.size() == KEY_SIZE)
      {
        keyCandidate.assign(keyRaw.begin(), keyRaw.end());

        if (m_UsePassphrase)
        {
          if (!PersistKeyLocked(keyCandidate))
          {
            LOG_WARNING("failed to migrate encryption key to passphrase-protected storage");
            SecureZero(keyCandidate);
            return false;
          }
        }

        ClearKeyLocked();
        m_Key = keyCandidate;
        LockKeyMemory();
        SecureZero(keyCandidate);
        return true;
      }

      LOG_WARNING("invalid encryption key, regenerating");
    }
  }

  std::vector<unsigned char> key(KEY_SIZE);
  if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1)
  {
    LOG_WARNING("failed to generate encryption key");
    SecureZero(key);
    return false;
  }

  if (!PersistKeyLocked(key))
  {
    SecureZero(key);
    return false;
  }

  ClearKeyLocked();
  m_Key = key;
  LockKeyMemory();
  SecureZero(key);
  return true;
}

bool CryptoUtil::PersistKeyLocked(const std::vector<unsigned char>& p_Key)
{
  if (m_KeyPath.empty()) return false;

  if (m_UsePassphrase)
  {
    std::string serialized;
    if (!EncryptKey(p_Key, serialized))
    {
      LOG_WARNING("failed to encrypt cache key for storage");
      return false;
    }

    FileUtil::WriteFile(m_KeyPath, serialized);
    chmod(m_KeyPath.c_str(), 0600);
    return true;
  }

  std::string keyRaw(reinterpret_cast<const char*>(p_Key.data()), p_Key.size());
  std::string keyHex = StrUtil::StrToHex(keyRaw);
  FileUtil::WriteFile(m_KeyPath, keyHex + "\n");
  chmod(m_KeyPath.c_str(), 0600);
  return true;
}

bool CryptoUtil::EncryptKey(const std::vector<unsigned char>& p_Key, std::string& p_Serialized)
{
  if (!m_UsePassphrase || m_Passphrase.empty())
  {
    LOG_WARNING("passphrase not set, cannot encrypt key");
    return false;
  }

  std::vector<unsigned char> salt(SALT_SIZE);
  std::vector<unsigned char> iv(IV_SIZE);
  std::vector<unsigned char> tag(TAG_SIZE);

  if ((RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) ||
      (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1))
  {
    LOG_WARNING("failed to generate key protection parameters");
    return false;
  }

  std::vector<unsigned char> derivedKey(KEY_SIZE);
  if (!DerivePassphraseKey(m_Passphrase, salt, derivedKey))
  {
    return false;
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr)
  {
    LOG_WARNING("failed to allocate cipher context for key protection");
    return false;
  }

  bool success = true;
  std::vector<unsigned char> cipher(KEY_SIZE);
  int outLen = 0;

  if (success && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
  {
    success = false;
  }

  if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1)
  {
    success = false;
  }

  if (success && EVP_EncryptInit_ex(ctx, nullptr, nullptr, derivedKey.data(), iv.data()) != 1)
  {
    success = false;
  }

  if (success &&
      EVP_EncryptUpdate(ctx, cipher.data(), &outLen, p_Key.data(), static_cast<int>(p_Key.size())) != 1)
  {
    success = false;
  }

  int tmpLen = 0;
  if (success && EVP_EncryptFinal_ex(ctx, cipher.data() + outLen, &tmpLen) != 1)
  {
    success = false;
  }

  outLen += tmpLen;
  cipher.resize(outLen);

  if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1)
  {
    success = false;
  }

  EVP_CIPHER_CTX_free(ctx);

  if (!success)
  {
    LOG_WARNING("failed to encrypt key material");
    return false;
  }

  std::ostringstream oss;
  oss << KEYFILE_MAGIC << "\n";
  oss << "salt=" << StrUtil::StrToHex(std::string(reinterpret_cast<const char*>(salt.data()), salt.size())) << "\n";
  oss << "iv=" << StrUtil::StrToHex(std::string(reinterpret_cast<const char*>(iv.data()), iv.size())) << "\n";
  oss << "tag=" << StrUtil::StrToHex(std::string(reinterpret_cast<const char*>(tag.data()), tag.size())) << "\n";
  oss << "ct=" << StrUtil::StrToHex(std::string(reinterpret_cast<const char*>(cipher.data()), cipher.size())) << "\n";

  p_Serialized = oss.str();
  return true;
}

bool CryptoUtil::DecryptStoredKey(const std::string& p_Data, std::vector<unsigned char>& p_Key)
{
  std::vector<std::string> lines = StrUtil::Split(p_Data, '\n');
  std::string saltHex;
  std::string ivHex;
  std::string tagHex;
  std::string ctHex;

  for (const std::string& lineRaw : lines)
  {
    std::string line = lineRaw;
    StrUtil::Trim(line);
    if (line.empty()) continue;

    if (StrUtil::StartsWith(line, "salt="))
    {
      saltHex = line.substr(5);
    }
    else if (StrUtil::StartsWith(line, "iv="))
    {
      ivHex = line.substr(3);
    }
    else if (StrUtil::StartsWith(line, "tag="))
    {
      tagHex = line.substr(4);
    }
    else if (StrUtil::StartsWith(line, "ct="))
    {
      ctHex = line.substr(3);
    }
  }

  if (saltHex.empty() || ivHex.empty() || tagHex.empty() || ctHex.empty())
  {
    LOG_WARNING("incomplete encrypted key data");
    return false;
  }

  std::string saltStr = StrUtil::StrFromHex(saltHex);
  std::string ivStr = StrUtil::StrFromHex(ivHex);
  std::string tagStr = StrUtil::StrFromHex(tagHex);
  std::string ctStr = StrUtil::StrFromHex(ctHex);

  if ((saltStr.size() != SALT_SIZE) || (ivStr.size() != IV_SIZE) || (tagStr.size() != TAG_SIZE))
  {
    LOG_WARNING("invalid encrypted key parameter sizes");
    return false;
  }

  std::vector<unsigned char> salt(saltStr.begin(), saltStr.end());
  std::vector<unsigned char> iv(ivStr.begin(), ivStr.end());
  std::vector<unsigned char> tag(tagStr.begin(), tagStr.end());
  std::vector<unsigned char> cipher(ctStr.begin(), ctStr.end());

  if (cipher.empty())
  {
    LOG_WARNING("encrypted key payload empty");
    return false;
  }

  std::vector<unsigned char> derived(KEY_SIZE);
  if (!DerivePassphraseKey(m_Passphrase, salt, derived))
  {
    return false;
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr)
  {
    LOG_WARNING("failed to allocate cipher context for key decryption");
    return false;
  }

  bool success = true;
  std::vector<unsigned char> plain(cipher.size());
  int len = 0;

  if (success && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
  {
    success = false;
  }

  if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1)
  {
    success = false;
  }

  if (success && EVP_DecryptInit_ex(ctx, nullptr, nullptr, derived.data(), iv.data()) != 1)
  {
    success = false;
  }

  if (success &&
      EVP_DecryptUpdate(ctx, plain.data(), &len, cipher.data(), static_cast<int>(cipher.size())) != 1)
  {
    success = false;
  }

  if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1)
  {
    success = false;
  }

  int finLen = 0;
  if (success && EVP_DecryptFinal_ex(ctx, plain.data() + len, &finLen) != 1)
  {
    success = false;
  }

  len += finLen;
  plain.resize(len);

  EVP_CIPHER_CTX_free(ctx);

  if (!success)
  {
    LOG_WARNING("failed to decrypt key material (invalid passphrase?)");
    return false;
  }

  if (plain.size() != KEY_SIZE)
  {
    LOG_WARNING("unexpected plain key size");
    return false;
  }

  p_Key = plain;
  return true;
}

bool CryptoUtil::DerivePassphraseKey(const std::string& p_Passphrase,
                                     const std::vector<unsigned char>& p_Salt,
                                     std::vector<unsigned char>& p_Derived)
{
  if (p_Derived.size() != KEY_SIZE)
  {
    p_Derived.resize(KEY_SIZE);
  }

  if (PKCS5_PBKDF2_HMAC(p_Passphrase.c_str(), static_cast<int>(p_Passphrase.size()),
                         p_Salt.data(), static_cast<int>(p_Salt.size()),
                         PBKDF2_ITERATIONS, EVP_sha256(),
                         static_cast<int>(p_Derived.size()), p_Derived.data()) != 1)
  {
    LOG_WARNING("failed to derive passphrase key");
    return false;
  }

  return true;
}

void CryptoUtil::ClearKeyLocked()
{
  if (m_Key.empty())
  {
    return;
  }

  UnlockKeyMemory();
  SecureZero(m_Key);
  m_Key.clear();
}

void CryptoUtil::LockKeyMemory()
{
#if defined(__unix__) || defined(__APPLE__)
  if (m_Key.empty())
  {
    m_KeyLocked = false;
    return;
  }

  if (!m_KeyLocked)
  {
    if (mlock(m_Key.data(), m_Key.size()) == 0)
    {
      m_KeyLocked = true;
    }
    else
    {
      m_KeyLocked = false;
      LOG_WARNING("failed to lock encryption key in memory");
    }
  }
#else
  m_KeyLocked = false;
#endif
}

void CryptoUtil::UnlockKeyMemory()
{
#if defined(__unix__) || defined(__APPLE__)
  if (m_KeyLocked && !m_Key.empty())
  {
    munlock(m_Key.data(), m_Key.size());
  }
#endif
  m_KeyLocked = false;
}

void CryptoUtil::SecureZero(std::vector<unsigned char>& p_Data)
{
  if (p_Data.empty()) return;

  volatile unsigned char* data = reinterpret_cast<volatile unsigned char*>(p_Data.data());
  for (size_t i = 0; i < p_Data.size(); ++i)
  {
    data[i] = 0;
  }

  p_Data.clear();
}
