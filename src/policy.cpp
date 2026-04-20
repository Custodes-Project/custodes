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
// Created: April 19, 2026
// Modified: April 19, 2026

#include "include/policy.hpp"

#include <algorithm>
#include <cassert>
#include <cctype>
#include <regex>
#include <string>

namespace custodes {
[[nodiscard]] const bool PolicyHandler::IsValidPassword(
    std::string_view password) {
  if (!this->CheckValidationRegex(password)) {
    return false;
  }
  if (!this->CheckMinLength(password)) {
    return false;
  }
  if (!this->CheckMaxLength(password)) {
    return false;
  }
  if (!this->CheckRequireCapital(password)) {
    return false;
  }
  return true;
}

void PolicyHandler::SetPasswordRule(PasswordPolicyKey key, std::string value) {
  this->password_rules_[key] = value;
}

[[nodiscard]] const bool PolicyHandler::CheckValidationRegex(
    std::string_view password) {
  // Ensure validation_regex is in map
  assert(this->password_rules_.find(PasswordPolicyKey::kValidationRegex) !=
         this->password_rules_.end());
  std::string validation_regex =
      this->password_rules_[PasswordPolicyKey::kValidationRegex];

  if (validation_regex.empty()) {
    return true;
  }

  std::regex re(validation_regex);
  return std::regex_match(password.begin(), password.end(), re);
}
[[nodiscard]] const bool PolicyHandler::CheckMinLength(
    std::string_view password) {
  // Ensure min_length is in map
  assert(this->password_rules_.find(PasswordPolicyKey::kMinLength) !=
         this->password_rules_.end());
  std::string min_length = this->password_rules_[PasswordPolicyKey::kMinLength];

  if (min_length.empty()) {
    return true;
  }

  // Check if password matches min_length
  int length = std::stoi(min_length);
  return password.length() >= length;
}
[[nodiscard]] const bool PolicyHandler::CheckMaxLength(
    std::string_view password) {
  // Ensure max_length is in map
  assert(this->password_rules_.find(PasswordPolicyKey::kMaxLength) !=
         this->password_rules_.end());
  std::string max_length = this->password_rules_[PasswordPolicyKey::kMaxLength];

  if (max_length.empty()) {
    return true;
  }

  // Check if password matches max_length
  int length = std::stoi(max_length);
  return password.length() <= length;
}
[[nodiscard]] const bool PolicyHandler::CheckRequireCapital(
    std::string_view password) {
  assert(this->password_rules_.find(PasswordPolicyKey::kRequireCapital) !=
         this->password_rules_.end());

  if (this->password_rules_[PasswordPolicyKey::kRequireCapital] == "false") {
    return true;
  }
  return std::any_of(password.begin(), password.end(),
                     [](char c) { return std::isupper(c); });
}
}  // namespace custodes
