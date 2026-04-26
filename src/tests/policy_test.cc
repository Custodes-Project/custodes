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

#include "../include/policy.hpp"

#include <gtest/gtest.h>

TEST(PolicyHandlerTest, RegexSucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_regex_string("foo bar");
  std::string test_case = "foo bar";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RegexPartialFail) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_regex_string("foo bar");
  std::string test_case = "foo";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RegexFail) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_regex_string("foo");
  std::string test_case = "bar";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MinLengthSucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_min_length(5);
  std::string test_case = "aaaaaaaaa";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MinLengthExactSucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_min_length(5);
  std::string test_case = "aaaaa";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MinLengthFail) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_min_length(5);
  std::string test_case = "aaaa";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MaxLengthSucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_max_length(5);
  std::string test_case = "aa";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MaxLengthExactSucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_max_length(5);
  std::string test_case = "aaaaa";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MaxLengthFail) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_max_length(5);
  std::string test_case = "aaaaaaaa";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RequireCapitalSucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_require_capital(true);
  std::string test_case = "Foo";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RequireCapitalFail) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_require_capital(true);
  std::string test_case = "foo";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RequireNumberSucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_require_number(true);
  std::string test_case = "Foo123";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RequireNumberFail) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_require_number(true);
  std::string test_case = "foo";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RequireSymbolSucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_require_symbol(true);
  std::string test_case = "Foo%";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RequireSymbolFail) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_require_symbol(true);
  std::string test_case = "foo";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MaxRepetitionSucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_max_repetition(3);
  std::string test_case = "foo";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MaxRepetitionExactSucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_max_repetition(3);
  std::string test_case = "fooo";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MaxRepetitionExactFail) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_max_repetition(3);
  std::string test_case = "foooo";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MaxSequenceSucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_max_sequence(3);
  std::string test_case = "aba";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MaxSequenceExactSucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_max_sequence(3);
  std::string test_case = "abc";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MaxSequenceExactFail) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_max_sequence(3);
  std::string test_case = "abcd";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MinEntropySucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_min_entropy(20);
  std::string test_case = "aba";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MinEntropyExactSucceed) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_min_entropy(21);
  std::string test_case = "abc";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MinEntropyFail) {
  custodes::PolicyHandler ph;
  ph.policy_config_.set_min_entropy(29);
  std::string test_case = "abcd";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, GenerateFromFile) {
  auto result = custodes::PolicyHandler::CreateFromFile("test_files/test_config.toml");
  if (std::holds_alternative<custodes::ContainerError>(result)) {
    std::cerr << std::get<custodes::ContainerError>(result).get_value() << std::endl;
    FAIL();
  }
  auto ph = std::get<custodes::PolicyHandler>(result);
  EXPECT_TRUE(ph.policy_config_.is_capital_required());
  EXPECT_FALSE(ph.policy_config_.is_symbol_required());
  EXPECT_EQ(ph.policy_config_.get_min_length(), 8);
}