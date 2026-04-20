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
// Created: April 17, 2026
// Modified: April 17, 2026

#ifndef CUSTODES_INCLUDE_POLICY_H_
#define CUSTODES_INCLUDE_POLICY_H_

#include <string>
#include <unordered_map>
#include <variant>

#include "store.hpp"

namespace custodes {
class PolicyHandler {
 public:
  [[nodiscard]] const bool IsValidPassword(std::string_view password);
  [[nodiscard]] const bool CanUserAccessStore(std::string_view username,
                                              std::string_view password);
  static std::variant<PolicyHandler, ContainerError> CreateFromFile(File file);
  void SetPasswordRule(std::string key, std::string value);

 private:
  /*
   * password_rules_ defines the password rules used inIsValidPassword.
   * All values are formatted as strings, but will be parsed as the following
   * type: validation_regex: string min_length: int max_length: int
   * require_capital: bool
   * require_number: bool
   * require_symbol: bool
   * max_repetition: int
   * max_sequence: int
   * min_entropy: int
   * max_attempts: int
   * When the PolicyHandler is created from file, appropriate values in
   * password_rules_ should be updated.
   */
  std::unordered_map<std::string, std::string> password_rules_ = {
      {"validation_regex", ""},    {"min_length", ""},
      {"max_length", ""},          {"require_capital", "false"},
      {"require_number", "false"}, {"require_symbol", "false"},
      {"max_repetition", ""},      {"max_sequence", ""},
      {"min_entropy", "0"},        {"max_attempts", ""}};

  [[nodiscard]] const bool CheckValidationRegex(std::string_view password);
  [[nodiscard]] const bool CheckMinLength(std::string_view password);
  [[nodiscard]] const bool CheckMaxLength(std::string_view password);
};

}  // namespace custodes

#endif
