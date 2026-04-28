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

#include "custodes.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "crypto.hpp"
#include "policy.hpp"
#include "store.hpp"

#include "sodium.h"

namespace custodes {

namespace {
custodes::File assemble_header(
  std::tuple<std::string, std::vector<std::tuple<
               std::string, custodes::SymmetricKey>>> header) {
  size_t total_size = 0;
  std::string user = std::get<0>(header);
  total_size += user.size() + 1; // user string
  for (auto d : std::get<1>(header)) {
    total_size += std::get<0>(d).size() + 1;
    total_size += 32; // symmetric key size
  }
  auto bytes = std::shared_ptr<unsigned char[]>(new unsigned char[total_size]);

  size_t offset = user.size() + 1;
  std::memcpy(bytes.get(), user.data(), user.size() + 1);
  for (auto d : std::get<1>(header)) {
    std::string doc = std::get<0>(d);
    custodes::SymmetricKey key = std::get<1>(d);
    std::memcpy(bytes.get() + offset, doc.data(), doc.size() + 1);
    offset += doc.size() + 1;
    std::memcpy(bytes.get() + offset, key.get(), 32);
    offset += 32;
  }

  return custodes::File(bytes, total_size);
}

uint32_t write_u32(uint32_t x) {
  return (x >> 24) | ((x >> 8) & 0xFF00) | ((x & 0xFF00) << 8) | (x << 24);
}

uint32_t read_u32(std::ifstream& input) {
  uint32_t raw;
  input.read(reinterpret_cast<char*>(&raw), sizeof(raw));
  return write_u32(raw);
}

std::shared_ptr<unsigned char[]> read_blob(std::ifstream& input, size_t size) {
  auto buffer = std::shared_ptr<unsigned char[]>(new unsigned char[size]);
  input.read(reinterpret_cast<char*>(buffer.get()), size);
  return buffer;
}

std::optional<custodes::File> locate_user_header(
  std::ifstream& input, size_t header_size, const PrivateKey& user_private_key,
  const PublicKey& creator_public_key) {
  size_t header_offset = 0;
  while (header_size > header_offset) {
    size_t record_size = read_u32(input);
    header_offset += record_size + 4;
    auto record = read_blob(input, record_size);
    AsymmetricStore asym_store(record, record_size);
    auto decrypt_result = asym_store.Decrypt(user_private_key, creator_public_key);
    if (decrypt_result.has_value()) {
      size_t remaining = header_size - header_offset;
      input.seekg(remaining, std::ios::cur);
      return decrypt_result.value();
    }
  }
  return std::nullopt;
}

std::string read_cstring(const unsigned char* buf, size_t buf_size,
                         size_t& offset) {
  std::string result;
  while (offset < buf_size && buf[offset] != '\0') {
    result += static_cast<char>(buf[offset++]);
  }
  offset++;
  return result;
}

std::tuple<std::string, std::vector<std::tuple<
             std::string, custodes::SymmetricKey>>> parse_header(
  custodes::File& file) {
  const unsigned char* buf = file.get_data();
  size_t buf_size = file.get_data_size();
  size_t offset = 0;

  std::string user = read_cstring(buf, buf_size, offset);
  std::vector<std::tuple<std::string, custodes::SymmetricKey>> pairs;
  while (offset < buf_size) {
    std::string doc_name = read_cstring(buf, buf_size, offset);
    auto key = std::shared_ptr<unsigned char[]>(new unsigned char[32]);
    std::memcpy(key.get(), buf + offset, 32);
    offset += 32;
    pairs.emplace_back(doc_name, key);
  }

  return {user, pairs};
}

std::vector<std::string> strip_paths(const std::vector<std::string>& paths) {
  std::vector<std::string> filenames;
  filenames.reserve(paths.size());
  for (auto& p: paths) {
    filenames.push_back(std::filesystem::path(p).stem().string());
  }
  return filenames;
}

} // namespace

std::optional<custodes::ContainerError> CreateContainer(
  const std::string& config_file, std::vector<std::string> input_files,
  std::vector<std::string> users,
  std::vector<std::string> user_public_keys,
  std::string creator_private_key) {
  std::vector<std::string> filenames = strip_paths(input_files);

  // parse config
  auto result = custodes::PolicyHandler::CreateFromFile(config_file);
  if (std::holds_alternative<custodes::ContainerError>(result)) {
    return std::get<custodes::ContainerError>(result);
  }
  custodes::PolicyHandler ph = std::get<custodes::PolicyHandler>(result);

  // generate ACM
  std::unordered_map<std::string, uint32_t> acm;
  int i = 1;
  for (auto r : ph.policy_config_.get_roles()) {
    for (auto ud : r.get_users_and_docs()) {
      acm[ud] = acm[ud] | i;
    }
    i = i << 1;
  }

  // split into users and docs
  std::unordered_map<std::string, uint32_t> user_acm;
  std::unordered_map<std::string, uint32_t> doc_acm;
  for (auto u : users) {
    user_acm[u] = acm[u];
  }
  for (auto d : filenames) {
    doc_acm[d] = acm[d];
  }

  // encrypt files
  std::vector<custodes::SymmetricKey> sym_keys;
  std::vector<custodes::SymmetricStore> sym_stores;
  for (auto f : input_files) {
    auto result_file = custodes::File::CreateFromFilePath(f);
    if (std::holds_alternative<custodes::FileError>(result_file)) {
      return std::get<custodes::FileError>(result_file);
    }
    custodes::File file = std::get<custodes::File>(result_file);
    custodes::SymmetricKey key = custodes::DeriveKey(f, "", custodes::CreateSalt());
    auto result_store = custodes::SymmetricStore::CreateFromFile(file, key);
    if (std::holds_alternative<custodes::FileError>(result_store)) {
      return std::get<custodes::FileError>(result_store);
    }
    custodes::SymmetricStore sym_store = std::get<custodes::SymmetricStore>(
      result_store);
    sym_keys.push_back(key);
    sym_stores.push_back(sym_store);
  }

  // distribute symkeys to users
  // [(user, [(doc, symkey)])]
  std::vector<std::tuple<std::string, std::vector<std::tuple<
                           std::string, custodes::SymmetricKey>>>> header;
  for (auto u : users) {
    uint32_t access_field = user_acm[u];
    std::vector<std::tuple<std::string, custodes::SymmetricKey>> doc_keys;
    for (int i = 0; i < filenames.size(); i++) {
      if ((doc_acm[filenames[i]] & access_field) != 0) {
        doc_keys.push_back({filenames[i], sym_keys[i]});
      }
    }
    header.push_back({u, doc_keys});
  }

  // encrypt headers
  std::vector<AsymmetricStore> encrypted_headers;
  for (int i = 0; i < users.size(); i++) {
    auto file = assemble_header(header[i]);
    auto user_pk = user_public_keys[i];
    auto pub_key = custodes::PublicKey::CreateFromString(user_pk);
    auto sec_key = custodes::PrivateKey::CreateFromString(creator_private_key);
    encrypted_headers.push_back(
      custodes::AsymmetricStore::EncryptFromFile(
        file, pub_key, sec_key));
  }

  // write file
  std::ofstream output;
  output.open("custodes_container.csdc", std::ios::binary| std::ios::trunc);
  output.write("\0\0\0\0", 4);
  uint32_t total_header_size = 0;
  for (auto h : encrypted_headers) {
    uint32_t size = write_u32(h.data_size_);
    output.write(reinterpret_cast<const char*>(&size), sizeof(size));
    output << h;
    total_header_size += sizeof(size) + h.data_size_;
  }

  for (auto f : sym_stores) {
    uint32_t size = write_u32(f.get_size());
    output.write(reinterpret_cast<const char*>(&size), sizeof(size));
    output << f;
  }
  output.seekp(0);
  uint32_t total_be = write_u32(total_header_size);
  output.write(reinterpret_cast<const char*>(&total_be), sizeof(total_be));
  output.close();

  return std::nullopt;
}

std::optional<custodes::ContainerError> ViewContainer(
  const std::string& container_file, const std::string& user,
  const custodes::PublicKey& creator_public_key,
  const custodes::PrivateKey& user_private_key,
  std::vector<std::tuple<std::string, custodes::File>>& decrypted_files) {
  std::ifstream input(container_file, std::ios::binary);
  size_t header_size = read_u32(input);
  auto header_result = locate_user_header(input, header_size, user_private_key,
                                          creator_public_key);
  if (!header_result.has_value()) {
    return ContainerError("User not in container.");
  }
  std::tuple<std::string, std::vector<std::tuple<
               std::string, custodes::SymmetricKey>>> header_data =
      parse_header(header_result.value());

  while (input.good()) {
    uint32_t blob_size = read_u32(input);
    auto buffer = read_blob(input, blob_size);
    custodes::SymmetricStore store(buffer, blob_size);
    for (auto pair: std::get<1>(header_data)) {
      auto key = std::get<1>(pair);
      auto sym_result = store.Decrypt(key);
      if (sym_result.has_value()) {
        decrypted_files.emplace_back(std::get<0>(pair), sym_result.value());
        break;
      }
    }
  }
  return std::nullopt;
}
} // namespace custodes