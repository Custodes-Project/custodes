#  This file is part of Custodes SDC.
#
# Custodes SDC is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# Custodes SDC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with Custodes SDC. If not, see <https://www.gnu.org/licenses/>.
#
# Author: Elijah Zimmerman
# Created: March 27, 2026
# Modified: April 19, 2026

# Add tests to CSDC_test target
target_sources(CSDC_test PRIVATE
        hello_test.cc
        libsodium_test.cc
        keychain_test.cc
        tomlplusplus_test.cc
        policy_test.cc
)

target_link_libraries(CSDC_test
        PRIVATE sodium
        PRIVATE keychain
        PRIVATE tomlplusplus::tomlplusplus
        PRIVATE Custodes_SDC
)
