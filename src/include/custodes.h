#ifndef CUSTODES_SDC_CUSTODES_H
#define CUSTODES_SDC_CUSTODES_H
#include <optional>
#include <vector>

#include "store.hpp"

std::optional<custodes::ContainerError> CreateContainer(
  char* config_files, char** input_files, char** user_public_keys);

std::optional<custodes::ContainerError> ViewContainer(
  const std::string& container_file, const std::string& user,
  custodes::PrivateKey user_private_key,
  std::vector<std::tuple<std::string, custodes::File>>& decrypted_files);


#endif