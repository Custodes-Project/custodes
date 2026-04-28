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
  std::string creator_private_key);

std::optional<custodes::ContainerError> ViewContainer(
  const std::string& container_file, const std::string& user,
  const custodes::PublicKey& creator_public_key,
  const custodes::PrivateKey& user_private_key,
  std::vector<std::tuple<std::string, custodes::File>>& decrypted_files);
} // namespace custodes

#endif