
//  This file is part of Custodes SDC.
//
// Custodes SDC is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// Custodes SDC is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// Custodes SDC. If not, see <https://www.gnu.org/licenses/>.
//
// Author: Samuel Jones
// Created: April 21, 2026
// Modified: April 21, 2026

#include "../include/store.hpp"

#include <gtest/gtest.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_sign_ed25519.h>

#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <variant>

#include "sodium.h"

// GTest is actually sick and can do stuff like this to clean up tests
class SymmetricStoreTest: public ::testing::Test {
protected:
  void SetUp() override {
    if (sodium_init() < 0) {
      FAIL() << "libsodium not initialized";
    }
  }

  custodes::SymmetricKey GenerateTestKey() {
    custodes::SymmetricKey key_buf(new unsigned char[crypto_secretbox_KEYBYTES]);
    crypto_secretbox_keygen(key_buf.get());
    return key_buf;
  }
};

TEST(FileTest, CreateFromStream) {
  using namespace custodes;

  // Create a buffer and copy into the stream
  const size_t buffer_length = 65;
  unsigned char buffer[buffer_length];
  std::istringstream stream(
      std::string(reinterpret_cast<const char*>(buffer), buffer_length));

  std::variant<File, FileError> return_variant = File::CreateFromStream(stream);
  File f = std::get<File>(return_variant);

  // Ensure data is properly copied
  unsigned char* file_data = f.get_data();
  EXPECT_TRUE(std::equal(std::begin(buffer), std::end(buffer), file_data));
}

TEST(FileTest, DoesContainSignature) {
  using namespace custodes;

  // Create a buffer and copy into the stream
  const size_t buffer_length = 65;
  unsigned char buffer[buffer_length];
  std::istringstream stream(
      std::string(reinterpret_cast<const char*>(buffer), buffer_length));

  std::variant<File, FileError> return_variant = File::CreateFromStream(stream);
  File f = std::get<File>(return_variant);

  EXPECT_TRUE(f.CanContainSignature());
}

TEST(FileTest, DoesNotContainSignature) {
  using namespace custodes;

  // Create a buffer and copy into the stream
  const size_t buffer_length = 20;
  unsigned char buffer[buffer_length];
  std::istringstream stream(
      std::string(reinterpret_cast<const char*>(buffer), buffer_length));

  std::variant<File, FileError> return_variant = File::CreateFromStream(stream);
  File f = std::get<File>(return_variant);

  EXPECT_FALSE(f.CanContainSignature());
}

TEST(FileTest, DoesNotContainSignatureExact) {
  using namespace custodes;

  // Create a buffer and copy into the stream
  const size_t buffer_length = 64;
  unsigned char buffer[buffer_length];
  std::istringstream stream(
      std::string(reinterpret_cast<const char*>(buffer), buffer_length));

  std::variant<File, FileError> return_variant = File::CreateFromStream(stream);
  File f = std::get<File>(return_variant);

  EXPECT_FALSE(f.CanContainSignature());
}

TEST(FileTest, CheckSignatureNoSignature) {
  using namespace custodes;

  // Create a buffer and copy into the stream
  const size_t buffer_length = 20;
  unsigned char buffer[buffer_length];
  std::istringstream stream(
      std::string(reinterpret_cast<const char*>(buffer), buffer_length));

  std::variant<File, FileError> return_variant = File::CreateFromStream(stream);
  File f = std::get<File>(return_variant);

  // Create a garbage publickey
  std::shared_ptr<unsigned char[]> pk_data(
      new unsigned char[crypto_sign_ed25519_PUBLICKEYBYTES]);
  PublicKey pubkey(pk_data, crypto_sign_ed25519_PUBLICKEYBYTES);

  FileSignature sig = std::get<FileSignature>(f.CheckSignature(pubkey));
  EXPECT_EQ(sig, FileSignature::kNoSignature);
}

TEST(FileTest, CheckSignatureInvalidSignature) {
  using namespace custodes;

  // Create a buffer and copy into the stream
  const size_t buffer_length = 100;
  unsigned char buffer[buffer_length];
  std::istringstream stream(
      std::string(reinterpret_cast<const char*>(buffer), buffer_length));

  std::variant<File, FileError> return_variant = File::CreateFromStream(stream);
  File f = std::get<File>(return_variant);

  // Create a garbage publickey
  std::shared_ptr<unsigned char[]> pk_data(
      new unsigned char[crypto_sign_ed25519_PUBLICKEYBYTES]);
  PublicKey pubkey(pk_data, crypto_sign_ed25519_PUBLICKEYBYTES);

  FileSignature sig = std::get<FileSignature>(f.CheckSignature(pubkey));
  EXPECT_EQ(sig, FileSignature::kInvalidSignature);
}

TEST(FileTest, CheckSignatureSignature) {
  using namespace custodes;

  // Create a keypair
  unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
  crypto_sign_ed25519_keypair(pk, sk);

  std::shared_ptr<unsigned char[]> pk_data(
      new unsigned char[crypto_sign_ed25519_PUBLICKEYBYTES]);
  std::memcpy(pk_data.get(), pk, crypto_sign_ed25519_PUBLICKEYBYTES);
  PublicKey pubkey(pk_data, crypto_sign_ed25519_PUBLICKEYBYTES);

  // Create a buffer and sign it
  const size_t buffer_length = 100;
  unsigned char buffer[buffer_length];

  unsigned char signed_buffer[crypto_sign_BYTES + buffer_length];
  unsigned long long signed_buffer_length;
  crypto_sign(signed_buffer, &signed_buffer_length, buffer, buffer_length, sk);

  std::istringstream stream(std::string(
      reinterpret_cast<const char*>(signed_buffer), signed_buffer_length));

  std::variant<File, FileError> return_variant = File::CreateFromStream(stream);
  File f = std::get<File>(return_variant);

  // Assert valid signature returns the message tuple
  auto result = f.CheckSignature(pubkey);
  auto& [message, message_len] = std::get<1>(result);
  EXPECT_EQ(message_len, buffer_length);
  EXPECT_TRUE(std::equal(buffer, buffer + buffer_length, message.get()));
}

TEST_F(SymmetricStoreTest, EncryptDecrypt) {
  std::string plaintext = "encrypt me";
  std::shared_ptr<unsigned char[]> plaintext_ptr(
    new unsigned char[plaintext.size()]);
  memcpy(plaintext_ptr.get(), plaintext.data(), plaintext.size());
  custodes::File plaintext_file(plaintext_ptr, plaintext.size());

  custodes::SymmetricKey key = GenerateTestKey();

  auto result = custodes::SymmetricStore::CreateFromFile(plaintext_file, key);
  ASSERT_TRUE(std::holds_alternative<custodes::SymmetricStore>(result));
  custodes::SymmetricStore store = std::get<custodes::SymmetricStore>(result);

  std::optional<custodes::File> decrypted_file = store.Decrypt(key);

  ASSERT_TRUE(decrypted_file.has_value());
  EXPECT_EQ(decrypted_file->get_data_size(), plaintext_file.get_data_size());
  EXPECT_EQ(
    memcmp(decrypted_file->get_data(), plaintext_file.get_data(), plaintext_file
      .get_data_size()), 0);
}

TEST_F(SymmetricStoreTest, EncryptionFail) {
  std::string plaintext = "encrypt me";
  std::shared_ptr<unsigned char[]> plaintext_ptr(
    new unsigned char[plaintext.size()]);
  memcpy(plaintext_ptr.get(), plaintext.data(), plaintext.size());
  custodes::File plaintext_file(plaintext_ptr, plaintext.size());

  custodes::SymmetricKey key = GenerateTestKey();

  auto result = custodes::SymmetricStore::CreateFromFile(plaintext_file, key);
  ASSERT_TRUE(std::holds_alternative<custodes::SymmetricStore>(result));
  custodes::SymmetricStore store = std::get<custodes::SymmetricStore>(result);

  unsigned char* raw = store.get_data_ptr();
  raw[crypto_secretbox_NONCEBYTES + 1] ^= 0xFF;

  std::optional<custodes::File> decrypted_file = store.Decrypt(key);
  EXPECT_FALSE(decrypted_file.has_value());
}