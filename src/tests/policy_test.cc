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
  ph.SetPasswordRule(custodes::PasswordPolicyKey::kValidationRegex, "foo bar");
  std::string test_case = "foo bar";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RegexPartialFail) {
  custodes::PolicyHandler ph;
  ph.SetPasswordRule(custodes::PasswordPolicyKey::kValidationRegex, "foo bar");
  std::string test_case = "foo";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RegexFail) {
  custodes::PolicyHandler ph;
  ph.SetPasswordRule(custodes::PasswordPolicyKey::kValidationRegex, "foo");
  std::string test_case = "bar";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MinLengthSucceed) {
  custodes::PolicyHandler ph;
  ph.SetPasswordRule(custodes::PasswordPolicyKey::kMinLength, "5");
  std::string test_case = "aaaaaaaaa";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MinLengthExactSucceed) {
  custodes::PolicyHandler ph;
  ph.SetPasswordRule(custodes::PasswordPolicyKey::kMinLength, "5");
  std::string test_case = "aaaaa";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MinLengthFail) {
  custodes::PolicyHandler ph;
  ph.SetPasswordRule(custodes::PasswordPolicyKey::kMinLength, "5");
  std::string test_case = "aaaa";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MaxLengthSucceed) {
  custodes::PolicyHandler ph;
  ph.SetPasswordRule(custodes::PasswordPolicyKey::kMaxLength, "5");
  std::string test_case = "aa";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MaxLengthExactSucceed) {
  custodes::PolicyHandler ph;
  ph.SetPasswordRule(custodes::PasswordPolicyKey::kMaxLength, "5");
  std::string test_case = "aaaaa";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, MaxLengthFail) {
  custodes::PolicyHandler ph;
  ph.SetPasswordRule(custodes::PasswordPolicyKey::kMaxLength, "5");
  std::string test_case = "aaaaaaaa";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RequireCapitalSucceed) {
  custodes::PolicyHandler ph;
  ph.SetPasswordRule(custodes::PasswordPolicyKey::kRequireCapital, "true");
  std::string test_case = "Foo";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RequireCapitalFail) {
  custodes::PolicyHandler ph;
  ph.SetPasswordRule(custodes::PasswordPolicyKey::kRequireCapital, "true");
  std::string test_case = "foo";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RequireNumberSucceed) {
  custodes::PolicyHandler ph;
  ph.SetPasswordRule(custodes::PasswordPolicyKey::kRequireNumber, "true");
  std::string test_case = "Foo123";
  EXPECT_TRUE(ph.IsValidPassword(test_case));
}

TEST(PolicyHandlerTest, RequireNumberFail) {
  custodes::PolicyHandler ph;
  ph.SetPasswordRule(custodes::PasswordPolicyKey::kRequireNumber, "true");
  std::string test_case = "foo";
  EXPECT_FALSE(ph.IsValidPassword(test_case));
}
