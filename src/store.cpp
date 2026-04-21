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
// Created: April 6, 2026
// Modified: April 21, 2026

#include "./include/store.hpp"

#include <sodium/crypto_box.h>
#include <sodium/crypto_sign.h>
#include <sodium/randombytes.h>

#include <cstddef>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <tuple>

namespace custodes {
std::variant<File, FileError> File::CreateFromFilePath(
    std::string_view filepath) {
  std::ifstream stream(std::string(filepath), std::ios::binary);
  if (!stream) return FileError("failed to open: " + std::string(filepath));
  return File::CreateFromStream(stream);
}
std::variant<File, FileError> File::CreateFromStream(std::istream& stream) {
  stream.seekg(0, std::ios::end);
  size_t stream_sizes = stream.tellg();
  stream.seekg(0);

  File f;
  f.data_ = std::make_unique<unsigned char[]>(stream_sizes);
  f.data_size_ = stream_sizes;
  stream.read(reinterpret_cast<char*>(f.data_.get()), stream_sizes);

  if (stream.bad()) return FileError("I/O error during read");
  if (static_cast<std::size_t>(stream.gcount()) != stream_sizes)
    return FileError("got: " + std::to_string(stream.gcount()) +
                     ",expected: " + std::to_string(stream_sizes) + " bytes");

  return f;
}

std::variant<FileSignature,
             std::tuple<std::shared_ptr<unsigned char[]>, unsigned long long>>
File::CheckSignature(PublicKey public_key) {
  /*
   * Determines if this file contains a valid signature, if any.
   If the file connot contain a signature, returns no signature.
   If it can contain one and its invalid, return invalid signature.
   Else returns the signed message and message length.
     */
  if (!this->CanContainSignature()) {
    return FileSignature::kNoSignature;
  }

  // Calculate message length and allocate space
  unsigned long long message_length = this->data_size_ - crypto_sign_BYTES;
  std::shared_ptr<unsigned char[]> message =
      std::make_unique<unsigned char[]>(message_length);

  if (crypto_sign_open(message.get(), &message_length, this->data_.get(),
                       this->data_size_, public_key.get_key_data()) != 0) {
    return FileSignature::kInvalidSignature;
  }

  return std::make_tuple(std::move(message), message_length);
}

bool File::CanContainSignature() {
  /*
   * Determines if the file can contain signature.
   If data_size_ > crypto_sign_BYTES return true; else false;
     */

  return this->data_size_ > crypto_sign_BYTES;
}

std::optional<File> AsymmetricStore::Decrypt(PrivateKey recipient_private_key,
                                             PublicKey sender_public_key) {}

AsymmetricStore AsymmetricStore::EncryptFromFile(
    File file, PublicKey recipient_public_key, PrivateKey sender_private_key) {
  // Get message data
  size_t message_length = file.get_data_size();
  unsigned char* message = file.get_data();

  // Allocate for nonce + ciphertext combined
  size_t cipher_length = message_length + crypto_box_MACBYTES;
  size_t store_length = crypto_box_NONCEBYTES + cipher_length;
  auto store = std::make_unique<unsigned char[]>(store_length);

  // Create a random nonce directly into the store buffer
  randombytes_buf(store.get(), crypto_box_NONCEBYTES);

  // Encrypt into store buffer after the nonce
  if (crypto_box_easy(store.get() + crypto_box_NONCEBYTES, message,
                      message_length,
                      store.get(),  // nonce is at the start of store
                      recipient_public_key.get_key_data(),
                      sender_private_key.get_key_data()) != 0) {
    throw std::runtime_error("Encryption failed");
  }

  return AsymmetricStore(std::move(store), store_length);
}

}  // namespace custodes
