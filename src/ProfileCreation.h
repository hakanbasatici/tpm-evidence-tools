#pragma once
#include <cstdint>

namespace tpm_evidence {
enum class Step { Configured, Create, Length, Identity, Scheme, Hash, Finalize, Readback };
constexpr std::uint32_t kBits = 2048;
constexpr std::uint32_t kIdentity = 0x00000008;
constexpr std::uint32_t kRsassa = 0x0014;
constexpr std::uint32_t kSha256 = 0x000b;
constexpr std::uint32_t kNotSupported = 0x80090029u;
enum class ReadDisposition { Matched, Unavailable, Rejected };
inline ReadDisposition AssessReadback(std::uint32_t error,std::uint32_t size,
                                     std::uint32_t value,std::uint32_t expected,bool bitmask=false) {
  if(error==kNotSupported) return ReadDisposition::Unavailable;
  if(error!=0||size!=4) return ReadDisposition::Rejected;
  return (bitmask ? (value&expected)==expected : value==expected)
         ? ReadDisposition::Matched : ReadDisposition::Rejected;
}

// Ops must own only its newly created unnamed key. No existing key is accepted.
template<class Ops> Step ConfigureEphemeralAik(Ops& ops) {
  if (!ops.CreateUnnamed()) return Step::Create;
  if (!ops.SetLength(kBits)) return Step::Length;
  if (!ops.SetIdentity(kIdentity)) return Step::Identity;
  if (!ops.SetScheme(kRsassa)) return Step::Scheme;
  if (!ops.SetHash(kSha256)) return Step::Hash;
  if (!ops.Finalize()) return Step::Finalize;
  if (!ops.CheckReadback(kBits, kIdentity, kRsassa, kSha256)) return Step::Readback;
  return Step::Configured;
}
inline const char* Name(Step step) {
  switch (step) {
    case Step::Configured: return "CONFIGURED";
    case Step::Create: return "CREATE_UNNAMED";
    case Step::Length: return "SET_LENGTH";
    case Step::Identity: return "SET_IDENTITY_POLICY";
    case Step::Scheme: return "SET_RSASSA_SCHEME";
    case Step::Hash: return "SET_SHA256_HASH";
    case Step::Finalize: return "FINALIZE";
    case Step::Readback: return "READBACK";
  }
  return "UNKNOWN";
}
}  // namespace tpm_evidence
