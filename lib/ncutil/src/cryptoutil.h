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

private:
  static bool EnsureKey();
  static bool LoadKeyLocked();

private:
  static std::string m_KeyPath;
  static std::vector<unsigned char> m_Key;
  static bool m_KeyLoaded;
  static std::mutex m_KeyMutex;
};
