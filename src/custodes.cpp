#include "custodes.h"

#include <cstring>
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
}

std::optional<custodes::ContainerError> CreateContainer(
  const std::string& config_file, std::vector<std::string> input_files,
  std::vector<std::string> users,
  std::vector<std::string> user_public_keys,
  custodes::PrivateKey creator_private_key) {
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
  for (auto d : input_files) {
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
    custodes::SymmetricKey key = custodes::DeriveKey(f, "");
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
    for (int i = 0; i < input_files.size(); i++) {
      if ((doc_acm[input_files[i]] & access_field) != 0) {
        doc_keys.push_back({input_files[i], sym_keys[i]});
      }
    }
    header.push_back({u, doc_keys});
  }

  // encrypt headers
  std::vector<AsymmetricStore> encrypted_headers;
  for (int i = 0; i < users.size(); i++) {
    auto file = assemble_header(header[i]);
    auto user_pk = user_public_keys[i];
    auto key_data = std::shared_ptr<unsigned char[]>(
      new unsigned char[user_pk.size()]);
    std::memcpy(key_data.get(), user_pk.data(), user_pk.size());
    auto pub_key = custodes::PublicKey(key_data, user_pk.size());
    encrypted_headers.push_back(
      custodes::AsymmetricStore::EncryptFromFile(
        file, pub_key, creator_private_key));
  }

  // write file
  std::ofstream output;
  output.open("custodes_container.csdc", std::ios::binary);
  output.write("\0\0\0\0", 4);
  uint32_t total_header_size = 0;
  for (auto h : encrypted_headers) {
    uint32_t size = write_u32(h.data_size_);
    output.write(reinterpret_cast<const char*>(&size), sizeof(size));
    output << h;
    total_header_size += sizeof(size) + h.data_size_;
  }

  uint32_t total_be = write_u32(total_header_size);
  output.seekp(0);
  output.write(reinterpret_cast<const char*>(&total_be), sizeof(total_be));
  output.seekp(0, std::ios::end);
  for (auto f : sym_stores) {
    uint32_t size = write_u32(f.get_size());
    output.write(reinterpret_cast<const char*>(&size), sizeof(size));
    output << f;
  }
  output.close();

  return std::nullopt;
}

std::optional<custodes::ContainerError> ViewContainer(
  const std::string& container_file, const std::string& user,
  custodes::PrivateKey user_private_key,
  std::vector<std::tuple<std::string, custodes::File>>& decrypted_files) {

}
} // namespace custodes