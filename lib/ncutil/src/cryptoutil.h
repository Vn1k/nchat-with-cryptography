// cryptoutil.h
//
// Copyright (c) 2025 Kristofer Berggren
// All rights reserved.
//
// nchat is distributed under the MIT license, see LICENSE for details.

#pragma once

#include <mutex>
#include <string>
#include <vector>

class CryptoUtil
{
public:
  static void Init(const std::string& p_KeyPath);
  static bool Encrypt(const std::string& p_PlainText, std::string& p_HexCipherText);
  static bool Decrypt(const std::string& p_HexCipherText, std::string& p_PlainText);
  static bool IsReady();
  static void SetPassphrase(const std::string& p_Passphrase);
  static bool ChangePassphrase(const std::string& p_OldPassphrase, const std::string& p_NewPassphrase);
  static bool IsPassphraseProtected();

private:
  static bool EnsureKey();
  static bool LoadKeyLocked();
  static bool PersistKeyLocked(const std::vector<unsigned char>& p_Key);
  static bool EncryptKey(const std::vector<unsigned char>& p_Key, std::string& p_Serialized);
  static bool DecryptStoredKey(const std::string& p_Data, std::vector<unsigned char>& p_Key);
  static bool DerivePassphraseKey(const std::string& p_Passphrase,
                                  const std::vector<unsigned char>& p_Salt,
                                  std::vector<unsigned char>& p_Derived);
  static void ClearKeyLocked();
  static void LockKeyMemory();
  static void UnlockKeyMemory();
  static void SecureZero(std::vector<unsigned char>& p_Data);

private:
  static std::string m_KeyPath;
  static std::vector<unsigned char> m_Key;
  static bool m_KeyLoaded;
  static std::mutex m_KeyMutex;
  static bool m_UsePassphrase;
  static std::string m_Passphrase;
  static bool m_KeyLocked;
};
