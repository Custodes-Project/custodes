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

#include "include/policy.hpp"

#include <algorithm>
#include <cassert>
#include <cctype>
#include <cstddef>
#include <regex>
#include <string>

#define TOML_EXCEPTIONS 0
#include "toml++/toml.hpp"

namespace custodes {

namespace {
LoggingLevel parse_logging_level(
  const std::optional<std::string_view>& option_string) {
  constexpr LoggingLevel DEFAULT_LEVEL = INFO;

  if (option_string) {
    std::string s(*option_string);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
      return std::tolower(c);
    });
    if (s == "debug") {
      return LoggingLevel::DEBUG;
    }
    if (s == "info") {
      return LoggingLevel::INFO;
    }
    if (s == "warn") {
      return LoggingLevel::WARN;
    }
    if (s == "error") {
      return LoggingLevel::ERROR;
    }
    return DEFAULT_LEVEL;
  }
  return DEFAULT_LEVEL;
}

void apply_rule(std::vector<Role>& roles, bool insertion, std::string_view role,
                std::string_view users_or_docs) {
  bool exists = false;
  for (auto& r : roles) {
    if (r.get_role() == role) {
      exists = true;
      if (insertion) {
        r.add_users_or_docs(users_or_docs);
      } else {
        r.remove_users_or_docs(users_or_docs);
      }
      break;
    }
  }
  if (!exists) {
    if (insertion) {
      roles.push_back(Role(role, users_or_docs));
    }
  }
}

const std::regex rule_regex(R"#((\+|-)\s+(\w+)\s+((?:\w+\s*)+))#");

std::variant<std::vector<Role>, ContainerError> parse_rules(
  const std::optional<std::string_view>& rules) {
  if (!rules) {
    return ContainerError("No rules provided.");
  }

  std::vector<std::tuple<std::string_view, std::string_view>> deletions;
  std::vector<Role> roles;
  std::stringstream ss((rules->data()));
  std::string line;
  while (std::getline(ss, line)) {
    if (line.empty()) {
      continue;
    }
    std::smatch match;
    if (!std::regex_search(line, match, rule_regex)) {
      return ContainerError("Invalid rule provided: " + line);
    }
    if (match[1].str() == "+") {
      apply_rule(roles, true, match[2].str(), match[3].str());
    } else {
      deletions.push_back(
        std::tuple<std::string_view, std::string_view>(
          match[2].str(), match[3].str()));
    }
  }
  for (auto d : deletions) {
    apply_rule(roles, false, std::get<0>(d), std::get<1>(d));
  }
  return roles;
}
}

Role::Role(std::string_view role, std::string_view users_or_docs) {
  role_ = std::move(role);
  std::stringstream ss(users_or_docs.data());
  std::string item;
  while (std::getline(ss, item, ' ')) {
    users_and_docs_.push_back(item);
  }
}

void Role::add_users_or_docs(std::string_view users_or_docs) {
  std::stringstream ss(users_or_docs.data());
  std::string item;
  while (std::getline(ss, item, ' ')) {
    users_and_docs_.push_back(item);
  }
}

void Role::remove_users_or_docs(std::string_view users_or_docs) {
  std::stringstream ss(users_or_docs.data());
  std::string item;
  while (std::getline(ss, item, ' ')) {
    users_and_docs_.erase(std::find(users_and_docs_.begin(),
                                    users_and_docs_.end(), item));
  }
}

std::variant<PolicyConfig, ContainerError> PolicyConfig::ParseFromFile(
  std::string_view file_path) {
  toml::parse_result result = toml::parse_file(file_path);
  if (!result) {
    return ContainerError("Unable to parse config file.");
  }
  toml::table tbl = std::move(result).table();
  toml::node_view<toml::node> passwords = tbl["passwords"];
  std::string regex_string = passwords["regex_string"].value_or("");
  std::optional<uint32_t> min_length = passwords["min_length"].value<
    uint32_t>();
  std::optional<uint32_t> max_length = passwords["max_length"].value<
    uint32_t>();
  bool require_capital = passwords["require_capital"].value_or(false);
  bool require_number = passwords["require_number"].value_or(false);
  bool require_symbol = passwords["require_symbol"].value_or(false);
  std::optional<uint32_t> max_repetition = passwords["max_repetition"].value<
    uint32_t>();
  std::optional<uint32_t> max_sequence = passwords["max_sequence"].value<
    uint32_t>();
  uint32_t min_entropy = passwords["min_entropy"].value_or(0);
  std::optional<uint32_t> max_attempts = passwords["max_attempts"].value<
    uint32_t>();
  LoggingLevel logging_level = parse_logging_level(
    tbl["logging"]["level"].value<std::string_view>());
  std::variant<std::vector<Role>, ContainerError> roles_result = parse_rules(
    tbl["roles"]["roles"].value<std::string_view>());
  if (std::holds_alternative<ContainerError>(roles_result)) {
    return std::get<ContainerError>(roles_result);
  }
  std::vector<Role> roles = std::get<std::vector<Role>>(roles_result);

  std::regex validation_regex(regex_string);

  return PolicyConfig(validation_regex, regex_string, min_length, max_length,
                      require_capital, require_number, require_symbol,
                      max_repetition, max_sequence, min_entropy, max_attempts,
                      logging_level, roles);
}

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

std::variant<PolicyHandler, ContainerError> PolicyHandler::
CreateFromFile(std::string_view file_path) {
  auto result = PolicyConfig::ParseFromFile(file_path);
  if (std::holds_alternative<ContainerError>(result)) {
    return std::get<ContainerError>(result);
  }
  return PolicyHandler(std::get<PolicyConfig>(result));
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
