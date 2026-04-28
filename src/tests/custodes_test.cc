#include "custodes.h"

#include <cstring>

#include "store.hpp"
#include "gtest/gtest.h"
#include "sodium/crypto_box.h"

std::pair<std::string, std::string> make_key_pair() {
  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(pk, sk);
  return {
    std::string(reinterpret_cast<const char*>(pk), crypto_box_PUBLICKEYBYTES),
    std::string(reinterpret_cast<const char*>(sk), crypto_box_SECRETKEYBYTES)
  };
}

TEST(CustodesTest, RoundTripTest) {
  auto creator_kp = make_key_pair();
  auto user_kp = make_key_pair();
  auto create_result = custodes::CreateContainer(
    "test_files/one_user_config.toml", {"test_files/test_doc1.xlsx"}, {"mike"},
    {user_kp.first}, creator_kp.second);
  ASSERT_FALSE(create_result.has_value());

  std::vector<std::tuple<std::string, custodes::File>> decrypted_files;
  auto view_result = custodes::ViewContainer("custodes_container.csdc", "mike",
                                             custodes::PublicKey::CreateFromString(
                                               creator_kp.first),
                                             custodes::PrivateKey::CreateFromString(
                                               user_kp.second),
                                             decrypted_files);
  ASSERT_FALSE(view_result.has_value());
  ASSERT_EQ(decrypted_files.size(), 1);

  auto original = custodes::File::CreateFromFilePath("test_files/test_doc1.xlsx");
  ASSERT_TRUE(std::holds_alternative<custodes::File>(original));
  custodes::File& original_file = std::get<custodes::File>(original);

  auto& [doc_name, decrypted_file] = decrypted_files[0];
  ASSERT_EQ(decrypted_file.get_data_size(), original_file.get_data_size());
  EXPECT_EQ(std::memcmp(decrypted_file.get_data(), original_file.get_data(), original_file.get_data_size()), 0);
}