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

#include <sodium.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretbox.h>

#include "./include/store.hpp"

namespace custodes {
Salt CreateSalt() {
  Salt salt(new unsigned char[crypto_pwhash_SALTBYTES]);
  randombytes_buf(salt.get(), crypto_pwhash_SALTBYTES);
  return salt;
}

SymmetricKey DeriveKey(std::string_view username, std::string_view password,
                       Salt salt) {
  SymmetricKey key(new unsigned char[crypto_secretbox_KEYBYTES]);

  std::string concat = std::string(username) + '\0' + std::string(password);

  if (crypto_pwhash(
          key.get(), crypto_secretbox_KEYBYTES, password.data(),
          password.size(), salt.get(), crypto_pwhash_OPSLIMIT_MODERATE,
          crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT) != 0) {
    throw std::runtime_error("Key derivation failed");
  }

  return key;
}
}  // namespace custodes
