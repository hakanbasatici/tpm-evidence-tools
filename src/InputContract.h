#pragma once
#include <algorithm>
#include <string>
#include <vector>
namespace tpm_evidence {
// Caller owns nonce generation/domain binding. Invalid input stops before opening any key.
inline bool DecodeNonce(const std::string& hex,std::vector<unsigned char>& out) {
  out.clear();
  if(hex.size()!=64 || !std::all_of(hex.begin(),hex.end(),[](unsigned char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');})) return false;
  auto digit=[](unsigned char c){return c<='9'?c-'0':c-'a'+10;};
  out.reserve(32);
  for(std::size_t i=0;i<64;i+=2)out.push_back(static_cast<unsigned char>((digit(hex[i])<<4)|digit(hex[i+1])));
  return true;
}
}
