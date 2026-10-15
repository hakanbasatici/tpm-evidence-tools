#include "ProfileCreation.h"
#include "InputContract.h"
#include <cassert>
#include <vector>
#include <iostream>
struct Fake {
  int fail = -1;
  std::vector<int> calls;
  bool Record(int i) { calls.push_back(i); return fail != i; }
  bool CreateUnnamed() { return Record(0); }
  bool SetLength(std::uint32_t value) { assert(value==2048); return Record(1); }
  bool SetIdentity(std::uint32_t value) { assert(value==8); return Record(2); }
  bool SetScheme(std::uint32_t value) { assert(value==0x14); return Record(3); }
  bool SetHash(std::uint32_t value) { assert(value==0x0b); return Record(4); }
  bool Finalize() { return Record(5); }
  bool CheckReadback(std::uint32_t bits,std::uint32_t identity,std::uint32_t scheme,std::uint32_t hash) {
    assert(bits==2048 && identity==8 && scheme==0x14 && hash==0x0b); return Record(6);
  }
};
int main() {
  using tpm_evidence::Step;
  Fake good;
  assert(tpm_evidence::ConfigureEphemeralAik(good)==Step::Configured);
  assert((good.calls==std::vector<int>{0,1,2,3,4,5,6}));
  Step failures[]={Step::Create,Step::Length,Step::Identity,Step::Scheme,Step::Hash,Step::Finalize,Step::Readback};
  for(int i=0;i<7;++i) {
    Fake bad; bad.fail=i;
    assert(tpm_evidence::ConfigureEphemeralAik(bad)==failures[i]);
    assert(bad.calls.size()==static_cast<std::size_t>(i+1));
    for(int j=0;j<=i;++j) assert(bad.calls[j]==j);
  }
  using tpm_evidence::ReadDisposition;
  for(auto expected:{2048u,8u,0x14u,0x0bu}) {
    assert(tpm_evidence::AssessReadback(0,4,expected,expected)==ReadDisposition::Matched);
    assert(tpm_evidence::AssessReadback(tpm_evidence::kNotSupported,0,0,expected)==ReadDisposition::Unavailable);
    assert(tpm_evidence::AssessReadback(0x80090010u,4,expected,expected)==ReadDisposition::Rejected);
    assert(tpm_evidence::AssessReadback(0,2,expected,expected)==ReadDisposition::Rejected);
    assert(tpm_evidence::AssessReadback(0,4,expected+1,expected)==ReadDisposition::Rejected);
  }
  assert(tpm_evidence::AssessReadback(0,4,9,8,true)==ReadDisposition::Matched);
  assert(tpm_evidence::AssessReadback(0,4,1,8,true)==ReadDisposition::Rejected);
  std::vector<unsigned char> nonce;
  assert(tpm_evidence::DecodeNonce(std::string(64,'0'),nonce) && nonce.size()==32);
  assert(tpm_evidence::DecodeNonce(std::string(64,'f'),nonce) && nonce[0]==255 && nonce[31]==255);
  for(const auto& invalid:std::vector<std::string>{"",std::string(63,'0'),std::string(65,'0'),std::string(64,'G'),std::string(64,'A'),std::string(63,'0')+" "}) {
    assert(!tpm_evidence::DecodeNonce(invalid,nonce) && nonce.empty());
  }
  std::cout << "PORTABLE_CONTROL_FLOW_AND_READBACK_CASES = 38_PASS; NO_WINDOWS_NO_TPM\n";
}
