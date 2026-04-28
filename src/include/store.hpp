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
// Created: April 6, 2026
// Modified: April 17, 2026

#ifndef CUSTODES_INCLUDE_STORE_H_
#define CUSTODES_INCLUDE_STORE_H_

#include <cstddef>
#include <istream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

#include "../../build/_deps/googletest-src/googletest/include/gtest/gtest_prod.h"

namespace custodes {
enum class FileSignature { kNoSignature, kInvalidSignature, kValidSignature };

typedef std::shared_ptr<unsigned char> Salt;

class ContainerError {
 public:
  ContainerError() = default;
  ContainerError(std::string value) : value_(std::move(value)) {}

  [[nodiscard]] const std::string& get_value() const { return value_; }

 private:
  std::string value_;
};

class FileError : public ContainerError {
  using ContainerError::ContainerError;
};

class PublicKey {
 private:
  std::shared_ptr<unsigned char[]> key_data_;
  size_t data_size_;

 public:
  PublicKey(std::shared_ptr<unsigned char[]> key_data, size_t data_size)
      : key_data_(std::move(key_data)), data_size_(data_size) {}
  static PublicKey CreateFromString(const std::string& key);
  [[nodiscard]] inline unsigned char* get_key_data() {
    return this->key_data_.get();
  }

  [[nodiscard]] inline size_t get_data_size() { return this->data_size_; }
};

class SymmetricStore;
class PrivateKey {
 private:
  std::shared_ptr<unsigned char[]> key_data_;
  size_t data_size_;

 public:
  explicit PrivateKey(std::shared_ptr<unsigned char[]> key_data, size_t data_size) : key_data_(
    std::move(key_data)), data_size_(data_size) {
  }
  static PrivateKey CreateFromString(const std::string& key);

  static std::variant<SymmetricStore, ContainerError> CreateFromUserKeyfile(
      SymmetricStore keyfile, std::string_view username,
      std::string_view password);
  static std::variant<SymmetricStore, ContainerError> CreateFromKeyring(
      std::string_view username, std::string_view password);
  static std::variant<SymmetricStore, ContainerError>
  CreateFromGuestCredentials(SymmetricStore keyfile);
  [[nodiscard]] inline unsigned char* get_key_data() {
    return this->key_data_.get();
  }
  [[nodiscard]] inline size_t get_data_size() {
    return data_size_;
  }
};

typedef std::shared_ptr<unsigned char[]> SymmetricKey;

class File {
 private:
  std::shared_ptr<unsigned char[]> data_;
  size_t data_size_;

 public:
  File(std::shared_ptr<unsigned char[]> data, size_t data_size)
      : data_(std::move(data)), data_size_(data_size) {}

  File() : data_(nullptr), data_size_(0) {}
  bool CanContainSignature();
  static std::variant<File, FileError> CreateFromFilePath(
      std::string_view filepath);
  static std::variant<File, FileError> CreateFromStream(std::istream& stream);

  std::variant<FileSignature,
               std::tuple<std::shared_ptr<unsigned char[]>, unsigned long long>>
  CheckSignature(PublicKey PublicKey);
  [[nodiscard]] inline unsigned char* get_data() { return this->data_.get(); }
  [[nodiscard]] inline size_t get_data_size() { return this->data_size_; }
};

typedef std::tuple<File, std::string> FileRolePair;

class SymmetricStore {
 public:
  SymmetricStore(std::shared_ptr<unsigned char[]> data, size_t data_size)
      : data_(std::move(data)), data_size_(data_size) {}
  std::optional<File> Decrypt(SymmetricKey symmetric_key);
  static std::variant<SymmetricStore, FileError> CreateFromFile(
      File file, SymmetricKey sym_key);
  [[nodiscard]] inline size_t get_size() {
    return data_size_;
  }

  friend std::ostream& operator<<(std::ostream& os, const SymmetricStore& store);

#ifdef CSDC_UNIT_TESTING
  unsigned char* get_data_ptr() { return data_.get(); }
#endif

 private:
  std::shared_ptr<unsigned char[]> data_;
  size_t data_size_;

  SymmetricStore() : data_size_(0) {}
};

class AsymmetricStore {
 public:
  AsymmetricStore(std::shared_ptr<unsigned char[]> data, size_t data_size)
      : data_(std::move(data)), data_size_(data_size) {}
  std::shared_ptr<unsigned char[]> data_;
  size_t data_size_;

  std::optional<File> Decrypt(PrivateKey recipient_private_key,
                              PublicKey sender_public_key);
  static std::variant<AsymmetricStore, FileError> CreateFromFile(File file);
  static AsymmetricStore EncryptFromFile(File file,
                                         PublicKey recipient_public_key,
                                         PrivateKey sender_private_key);
  friend std::ostream& operator<<(std::ostream& os, const AsymmetricStore& store);
};

class SymmetricStoreCollection {
 public:
  explicit SymmetricStoreCollection(
      std::unordered_map<std::string, SymmetricStore> collection)
      : collection_(std::move(collection)) {}
  std::unordered_map<std::string, SymmetricStore> collection_;
};

class AsymmetricStoreCollection {
 public:
  std::unordered_map<std::string, AsymmetricStore> collection_;
};

class PublicKeyCollection {
 public:
  std::unordered_map<std::string, PublicKey> collection_;
};

}  // namespace custodes
#endif  // CUSTODES_INCLUDE_STORE_H_
