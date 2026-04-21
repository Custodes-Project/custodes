
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
// Created: April 21, 2026
// Modified: April 21, 2026

#include "../include/store.hpp"

#include <gtest/gtest.h>

#include <sstream>
#include <string>
#include <variant>

TEST(FileTest, CreateFromStream) {
  using namespace custodes;

  // Create a buffer and copy into the stream
  const size_t buffer_length = 65;
  unsigned char buffer[buffer_length];
  std::istringstream stream(
      std::string(reinterpret_cast<const char*>(buffer), buffer_length));

  std::variant<File, FileError> return_variant = File::CreateFromStream(stream);
  File f = std::get<File>(return_variant);

  // Ensure data is properly copied
  unsigned char* file_data = f.get_data();
  EXPECT_TRUE(std::equal(std::begin(buffer), std::end(buffer), file_data));
}
