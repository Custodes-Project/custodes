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


#ifndef CUSTODES_INCLUDE_SESSION_H_
#define CUSTODES_INCLUDE_SESSION_H_
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "policy.hpp"
#include "store.hpp"

namespace custodes {
class SessionHandler {
 private:
  std::string username_;
  PrivateKey private_key_;

 protected:
  SessionHandler(std::string username,
                 AsymmetricStore keystore);  // Unclear based on spec if
                                             // keystore is right type.
 public:
  static std::variant<SessionHandler, ContainerError> CreateUserFileSession(
      std::string_view username, std::string_view password,
      SymmetricStore keyfile);
  static std::variant<SessionHandler, ContainerError> CreateUserKeyringSession(
      std::string_view username, std::string_view password,
      std::string_view package_name, std::string_view service_name);
  static std::variant<SessionHandler, ContainerError> CreateGuestSession(
      SymmetricStore keyfile);
};

class SecureDataContainer {
 private:
  SessionHandler user_session_;
  PolicyHandler policy_handler_;
  SymmetricStoreCollection document_collection_;
  SymmetricStoreCollection user_key_collection_;
  AsymmetricStoreCollection document_master_key_collection_;
  PublicKeyCollection user_public_keys_;
  std::vector<FileRolePair> unencrypted_files_collection_;

 public:
  std::optional<ContainerError> SetUserFileSession(std::string_view username,
                                                   std::string_view password);
  std::optional<ContainerError> SetUserKeyringSession(
      std::string_view username, std::string_view password,
      std::string_view package_name, std::string_view service_name);
  std::optional<ContainerError> SetGuestSession();
  std::optional<ContainerError> AddFile(FileRolePair document);
  std::variant<std::vector<std::string>, ContainerError>
  GetAvailableDocuments();
  std::variant<File, ContainerError> GetDocument(std::string_view document_id);
  void Commit();
};
}  // namespace custodes

#endif
