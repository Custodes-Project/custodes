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
  if (!this->CheckMaxRepetition(password)) {
    return false;
  }
  if (!this->CheckMaxSequence(password)) {
    return false;
  }
  if (!this->CheckMinEntropy(password)) {
    return false;
  }
  return true;
}

[[nodiscard]] const bool PolicyHandler::CheckValidationRegex(
    std::string_view password) {
  if (policy_config_.get_regex_string().empty()) {
    return true;
  }

  return std::regex_match(password.begin(), password.end(),
                          policy_config_.get_validation_regex());
}
[[nodiscard]] const bool PolicyHandler::CheckMinLength(
    std::string_view password) {
  // Ensure min_length is in map
  if (!policy_config_.is_min_length_set()) {
    return true;
  }

  // Check if password matches min_length
  return password.length() >= policy_config_.get_min_length();
}
[[nodiscard]] const bool PolicyHandler::CheckMaxLength(
    std::string_view password) {
  if (!policy_config_.is_max_length_set()) {
    return true;
  }

  return password.length() <= policy_config_.get_max_length();
}

[[nodiscard]] const bool PolicyHandler::CheckRequireCapital(
    std::string_view password) {
  if (!policy_config_.is_capital_required()) {
    return true;
  }
  return std::any_of(password.begin(), password.end(),
                     [](char c) { return std::isupper(c); });
}

[[nodiscard]] const bool PolicyHandler::CheckRequireNumber(
    std::string_view password) {
  if (!policy_config_.is_number_required()) {
    return true;
  }
  return std::any_of(password.begin(), password.end(),
                     [](char c) { return std::isdigit(c); });
}

[[nodiscard]] const bool PolicyHandler::CheckRequireSymbol(
    std::string_view password) {
  if (!policy_config_.is_symbol_required()) {
    return true;
  }
  return std::any_of(password.begin(), password.end(),
                     [](char c) { return !std::isalnum(c); });
}

[[nodiscard]] const bool PolicyHandler::CheckMaxRepetition(
    std::string_view password) {
  if (!policy_config_.is_max_repetition_set()) {
    return true;
  }

  if (policy_config_.get_max_repetition() == 0 && password.empty()) {
    return true;
  }

  int ct = 1;
  for (size_t i = 1; i < password.length(); i++) {
    if (password[i] == password[i - 1]) {
      ct++;
    } else {
      ct = 1;
    }

    if (ct > policy_config_.get_max_repetition()) {
      return false;
    }
  }

  return true;
}

[[nodiscard]] const bool PolicyHandler::CheckMaxSequence(
    std::string_view password) {
  if (!policy_config_.is_max_sequence_set()) {
    return true;
  }

  // 0 concurrent characters is only possible if string is empty
  if (policy_config_.get_max_sequence() == 0 && password.empty()) {
    return true;
  }

  int ct = 1;
  for (size_t i = 1; i < password.length(); i++) {
    if (password[i] == password[i - 1] + 1) {
      ct++;
    } else {
      ct = 1;
    }

    if (ct > policy_config_.get_max_sequence()) {
      return false;
    }
  }

  return true;
}

[[nodiscard]] const bool PolicyHandler::CheckMinEntropy(
    std::string_view password) {
  /*
   * E = (length) & log2(size of character pool)
   * Given ASCII characters, log2(size of character pool) = log2(128) = 7
   */
  // Check if password matches min_entropy
  int entropy = password.length() * 7;
  return entropy >= policy_config_.get_min_entropy();
}
}  // namespace custodes
