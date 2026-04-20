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
#include <cstddef>
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
  if (!this->CheckRequireNumber(password)) {
    return false;
  }
  if (!this->CheckRequireSymbol(password)) {
    return false;
  }
  if (!this->CheckMaxRepitition(password)) {
    return false;
  }
  if (!this->CheckMaxSequence(password)) {
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

[[nodiscard]] const bool PolicyHandler::CheckRequireNumber(
    std::string_view password) {
  assert(this->password_rules_.find(PasswordPolicyKey::kRequireNumber) !=
         this->password_rules_.end());

  if (this->password_rules_[PasswordPolicyKey::kRequireNumber] == "false") {
    return true;
  }
  return std::any_of(password.begin(), password.end(),
                     [](char c) { return std::isdigit(c); });
}

[[nodiscard]] const bool PolicyHandler::CheckRequireSymbol(
    std::string_view password) {
  assert(this->password_rules_.find(PasswordPolicyKey::kRequireSymbol) !=
         this->password_rules_.end());

  if (this->password_rules_[PasswordPolicyKey::kRequireSymbol] == "false") {
    return true;
  }
  return std::any_of(password.begin(), password.end(),
                     [](char c) { return !std::isalnum(c); });
}

[[nodiscard]] const bool PolicyHandler::CheckMaxRepitition(
    std::string_view password) {
  // Ensure max_length is in map
  assert(this->password_rules_.find(PasswordPolicyKey::kMaxRepitition) !=
         this->password_rules_.end());
  std::string max_rep_str =
      this->password_rules_[PasswordPolicyKey::kMaxRepitition];

  if (max_rep_str.empty()) {
    return true;
  }

  // Check if password matches max_length
  int max_rep = std::stoi(max_rep_str);

  // 0 concurrent characters is only possible if string is empty
  if (max_rep == 0) {
    return password.length();
  }

  int ct = 1;
  for (size_t i = 1; i < max_rep_str.length(); i++) {
    if (max_rep_str[i] == max_rep_str[i - 1]) {
      ct++;
    } else {
      ct = 1;
    }

    if (ct > max_rep) {
      return false;
    }
  }

  return true;
}

[[nodiscard]] const bool PolicyHandler::CheckMaxSequence(
    std::string_view password) {
  // Ensure max_sequence is in map
  assert(this->password_rules_.find(PasswordPolicyKey::kMaxRepitition) !=
         this->password_rules_.end());
  std::string max_seq_str =
      this->password_rules_[PasswordPolicyKey::kMaxRepitition];

  if (max_seq_str.empty()) {
    return true;
  }

  // Check if password matches max_sequence
  int max_seq = std::stoi(max_seq_str);

  // 0 concurrent characters is only possible if string is empty
  if (max_seq == 0) {
    return password.length();
  }

  int ct = 1;
  for (size_t i = 1; i < max_seq_str.length(); i++) {
    if (max_seq_str[i] == max_seq_str[i - 1] + 1) {
      ct++;
    } else {
      ct = 1;
    }

    if (ct > max_seq) {
      return false;
    }
  }

  return true;
}
}  // namespace custodes
