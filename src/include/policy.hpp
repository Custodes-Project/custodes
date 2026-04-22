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

#include <cstdint>
#include <optional>
#include <regex>
#include <string>
#include <unordered_map>
#include <variant>

#include "store.hpp"

namespace custodes {

enum class PasswordPolicyKey {
  kValidationRegex,
  kMinLength,
  kMaxLength,
  kRequireCapital,
  kRequireNumber,
  kRequireSymbol,
  kMaxRepetition,
  kMaxSequence,
  kMinEntropy,
  kMaxAttempts
};

enum LoggingLevel {
  DEBUG,
  WARN,
  INFO,
  ERROR,
};

class Role {
 public:
  explicit Role(std::string_view role_or_doc, ...);

 private:
  std::string role_or_doc_;
  std::vector<std::string> users_;
};

class PolicyConfig {
 public:
  static std::optional<PolicyConfig> ParseFromFile(std::string_view file_path);
  const std::regex get_validation_regex() { return validation_regex_; }
  [[nodiscard]] inline const bool is_min_length_set() {
    return min_length_.has_value();
  }
  [[nodiscard]] inline const bool is_max_length_set() {
    return max_length_.has_value();
  }
  [[nodiscard]] inline const bool is_max_repetition_set() {
    return max_repetition_.has_value();
  }
  [[nodiscard]] inline const bool is_max_sequence_set() {
    return max_sequence_.has_value();
  }
  [[nodiscard]] inline const bool is_max_attempts_set() {
    return max_attempts_.has_value();
  }

  [[nodiscard]] inline const uint32_t get_min_length() {
    return min_length_.value();
  }

  [[nodiscard]] inline const uint32_t get_max_length() {
    return max_length_.value();
  }

  [[nodiscard]] inline const bool is_capital_required() {
    return require_capital_;
  }

  [[nodiscard]] inline const bool is_number_required() {
    return require_number_;
  }

  [[nodiscard]] inline const bool is_symbol_required() {
    return require_symbol_;
  }

  [[nodiscard]] inline const uint32_t get_max_repetition() {
    return max_repetition_.value();
  }

  [[nodiscard]] inline const uint32_t get_max_sequence() {
    return get_max_sequence();
  }

  [[nodiscard]] inline const uint32_t get_min_entropy() { return min_entropy_; }

  [[nodiscard]] inline const uint32_t get_max_attempts() {
    return max_attempts_.value();
  }

  [[nodiscard]] inline const LoggingLevel get_logging_level() {
    return logging_level_;
  }

  [[nodiscard]] inline const std::vector<Role> get_roles() { return roles_; }

  inline void set_validation_regex(std::regex regex) {
    validation_regex_ = regex;
  }
  inline void set_min_length(uint32_t min_length) { min_length_ = min_length; }
  inline void set_max_length(uint32_t max_length) { max_length_ = max_length; }
  inline void set_require_capital(bool require_capital) {
    require_capital_ = require_capital;
  }
  inline void set_require_number(bool require_number) {
    require_number_ = require_number;
  }
  inline void set_require_symbol(bool require_symbol) {
    require_symbol_ = require_symbol;
  }
  inline void set_max_repetition(uint32_t max_repetition) {
    max_repetition_ = max_repetition;
  }
  inline void set_max_sequence(uint32_t max_sequence) {
    max_sequence_ = max_sequence;
  }
  inline void set_min_entropy(uint32_t min_entropy) {
    min_entropy_ = min_entropy;
  }
  inline void set_max_attempts(uint32_t max_attempts) {
    max_attempts_ = max_attempts;
  }
  inline void set_logging_level(LoggingLevel logging_level) {
    logging_level_ = logging_level;
  }
  inline void set_roles(std::vector<Role> roles) { roles_ = roles; }

 private:
  std::regex validation_regex_;
  std::optional<uint32_t> min_length_;
  std::optional<uint32_t> max_length_;
  bool require_capital_ = false;
  bool require_number_ = false;
  bool require_symbol_ = false;
  std::optional<uint32_t> max_repetition_;
  std::optional<uint32_t> max_sequence_;
  uint32_t min_entropy_ = 0;
  std::optional<uint32_t> max_attempts_;
  LoggingLevel logging_level_ = INFO;
  std::vector<Role> roles_;

  PolicyConfig();
};

class PolicyHandler {
 public:
  [[nodiscard]] const bool IsValidPassword(std::string_view password);
  [[nodiscard]] const bool CanUserAccessStore(std::string_view username,
                                              std::string_view password);
  static std::variant<PolicyHandler, ContainerError> CreateFromFile(File file);
  void SetPasswordRule(PasswordPolicyKey key, std::string value);

 private:
  PolicyConfig policy_config_;
  [[nodiscard]] const bool CheckValidationRegex(std::string_view password);
  [[nodiscard]] const bool CheckMinLength(std::string_view password);
  [[nodiscard]] const bool CheckMaxLength(std::string_view password);
  [[nodiscard]] const bool CheckRequireCapital(std::string_view password);
  [[nodiscard]] const bool CheckRequireNumber(std::string_view password);
  [[nodiscard]] const bool CheckRequireSymbol(std::string_view password);
  [[nodiscard]] const bool CheckMaxRepetition(std::string_view password);
  [[nodiscard]] const bool CheckMaxSequence(std::string_view password);
  [[nodiscard]] const bool CheckMinEntropy(std::string_view password);
};

}  // namespace custodes

#endif
