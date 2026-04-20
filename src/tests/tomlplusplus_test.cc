//  This file is part of Custodes SDC.
//
// Custodes SDC is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//
// Custodes SDC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Custodes SDC. If not, see <https://www.gnu.org/licenses/>.

#include <gtest/gtest.h>

#include "toml++/toml.hpp"

static constexpr auto source = R"(
    [password]
    min_length = 8
    require_capital = true
    require_number = true
    require_symbol = true
    max_attempts = 3

    [logging]
    level = "debug"

    [roles]
    roles = """
    + a z x
    + b x y
    - a z
    """
)";

TEST(TomlPlusPlusTest, Integration) {
    toml::table tbl;
    try {
        tbl = toml::parse(source);
    } catch (const toml::parse_error& err) {
        std::cerr << "Parsing failed:\n" << err << "\n";
        FAIL();
    }
    EXPECT_EQ(tbl["password"]["min_length"], 8);
    EXPECT_TRUE(tbl["password"]["require_capital"]);
    EXPECT_FALSE(tbl["password"]["max_repetition"].value_or(false));
    EXPECT_EQ(tbl["logging"]["level"], "debug");
}