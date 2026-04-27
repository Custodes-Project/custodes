#ifndef CUSTODES_SDC_CUSTODES_H
#define CUSTODES_SDC_CUSTODES_H
#include <optional>
#include <vector>

#include "store.hpp"

namespace custodes {
std::optional<custodes::ContainerError> CreateContainer(
  const std::string& config_file, std::vector<std::string> input_files,
  std::vector<std::string> users,
  std::vector<std::string> user_public_keys,
  custodes::PrivateKey creator_private_key);

std::optional<custodes::ContainerError> ViewContainer(
  const std::string& container_file, const std::string& user,
  custodes::PrivateKey user_private_key,
  std::vector<std::tuple<std::string, custodes::File>>& decrypted_files);
} // namespace custodes

#endif