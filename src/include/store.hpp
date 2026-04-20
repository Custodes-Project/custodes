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

#include <istream>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

namespace custodes {
enum class FileSignature { kNoSignature, kInvalidSignature, kValidSignature };

typedef std::unique_ptr<unsigned char> Salt;

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

typedef std::unique_ptr<unsigned char> PublicKey;

class SymmetricStore;
class PrivateKey {
 private:
  std::unique_ptr<unsigned char> key_data_;

 public:
  static std::variant<SymmetricStore, ContainerError> CreateFromUserKeyfile(
      SymmetricStore keyfile, std::string_view username,
      std::string_view password);
  static std::variant<SymmetricStore, ContainerError> CreateFromKeyring(
      std::string_view username, std::string_view password);
  static std::variant<SymmetricStore, ContainerError>
  CreateFromGuestCredentials(SymmetricStore keyfile);
};

typedef std::unique_ptr<unsigned char> SymmetricKey;

class File {
 private:
  std::unique_ptr<unsigned char[]> data_;

 public:
  static std::variant<File, FileError> CreateFromFilePath(
      std::string_view filepath);
  static std::variant<File, FileError> CreateFromStream(std::istream& stream);

  FileSignature CheckSignature(PublicKey PublicKey);
};

typedef std::tuple<File, std::string> FileRolePair;

class SymmetricStore {
 private:
  Salt salt_;

 public:
  File Decrypt(SymmetricKey symmetric_key);
  static std::variant<SymmetricStore, FileError> CreateFromFile(File file);
};

class AsymmetricStore {
  File Decrypt(PrivateKey private_key);
  static std::variant<AsymmetricStore, FileError> CreateFromFile(File file);
};

class SymmetricStoreCollection {
 public:
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
