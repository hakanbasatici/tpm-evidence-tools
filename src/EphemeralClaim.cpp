#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <tbs.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "ProfileCreation.h"
#include "InputContract.h"
#pragma comment(lib,"ncrypt.lib")
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"tbs.lib")

namespace {
class Handle {
 public:
  NCRYPT_HANDLE value=0;
  ~Handle() { if(value) NCryptFreeObject(value); }
  Handle()=default; Handle(const Handle&)=delete; Handle& operator=(const Handle&)=delete;
};
class EphemeralOps {
 public:
  explicit EphemeralOps(NCRYPT_PROV_HANDLE p):provider(p){}
  Handle key;
  SECURITY_STATUS status=ERROR_SUCCESS;
  bool created=false, finalized=false, readbackComplete=true;
  const char* failedReadProperty="NONE";
  struct Observation { const char* name; DWORD code=0,size=0,value=0; };
  Observation observations[4]={{"LENGTH"},{"IDENTITY"},{"SCHEME"},{"HASH"}};
  bool CreateUnnamed() {
    status=NCryptCreatePersistedKey(provider,reinterpret_cast<NCRYPT_KEY_HANDLE*>(&key.value),
                                  BCRYPT_RSA_ALGORITHM,nullptr,0,0);
    created=(status==ERROR_SUCCESS); return created;
  }
  bool Set(LPCWSTR property,std::uint32_t value) {
    DWORD v=value;
    status=NCryptSetProperty(static_cast<NCRYPT_KEY_HANDLE>(key.value),property,
                            reinterpret_cast<PBYTE>(&v),sizeof(v),0);
    return status==ERROR_SUCCESS;
  }
  bool SetLength(std::uint32_t value) { return Set(NCRYPT_LENGTH_PROPERTY,value); }
  bool SetIdentity(std::uint32_t value) { return Set(NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,value); }
  bool SetScheme(std::uint32_t value) { return Set(NCRYPT_PCP_RSA_SCHEME_PROPERTY,value); }
  bool SetHash(std::uint32_t value) { return Set(NCRYPT_PCP_RSA_SCHEME_HASH_ALG_PROPERTY,value); }
  bool Finalize() {
    status=NCryptFinalizeKey(static_cast<NCRYPT_KEY_HANDLE>(key.value),NCRYPT_SILENT_FLAG);
    finalized=(status==ERROR_SUCCESS); return finalized;
  }
  bool CheckReadback(std::uint32_t bits,std::uint32_t identity,std::uint32_t scheme,std::uint32_t hash) {
    const LPCWSTR properties[]={NCRYPT_LENGTH_PROPERTY,NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                              NCRYPT_PCP_RSA_SCHEME_PROPERTY,NCRYPT_PCP_RSA_SCHEME_HASH_ALG_PROPERTY};
    const std::uint32_t expected[]={bits,identity,scheme,hash};
    for(int i=0;i<4;++i) {
      auto& item=observations[i];
      status=NCryptGetProperty(static_cast<NCRYPT_KEY_HANDLE>(key.value),properties[i],
                              reinterpret_cast<PBYTE>(&item.value),sizeof(item.value),&item.size,0);
      item.code=static_cast<DWORD>(status);
      const auto verdict=tpm_evidence::AssessReadback(item.code,item.size,item.value,expected[i],i==1);
      if(verdict==tpm_evidence::ReadDisposition::Unavailable) { readbackComplete=false; continue; }
      if(verdict==tpm_evidence::ReadDisposition::Rejected) {
        failedReadProperty=item.name;
        if(status==ERROR_SUCCESS) status=NTE_BAD_DATA;
        return false;
      }
    }
    status=ERROR_SUCCESS;
    return true;
  }
  void WriteReadbacks(std::ostream& out) const {
    out<<"[";
    for(int i=0;i<4;++i) {
      if(i) out<<",";
      const auto& item=observations[i];
      out<<"{\"property\":\""<<item.name<<"\",\"detail\":"<<item.code
         <<",\"size\":"<<item.size<<",\"value\":"<<item.value
         <<",\"unavailable\":"<<(item.code==tpm_evidence::kNotSupported?"true":"false")<<"}";
    }
    out<<"]";
  }

 private:
  NCRYPT_PROV_HANDLE provider;
};
std::string Hex(const std::vector<unsigned char>& data) {
  std::ostringstream out; out<<std::hex<<std::setfill('0');
  for(auto b:data) out<<std::setw(2)<<static_cast<unsigned>(b);
  return out.str();
}
bool Hash(const unsigned char* data,std::size_t size,std::vector<unsigned char>* out) {
  BCRYPT_ALG_HANDLE algorithm=nullptr;
  if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0) return false;
  out->assign(32,0);
  const NTSTATUS result=BCryptHash(algorithm,nullptr,0,const_cast<PUCHAR>(data),static_cast<ULONG>(size),out->data(),32);
  BCryptCloseAlgorithmProvider(algorithm,0); return result>=0;
}
int Fail(const char* stage,SECURITY_STATUS code,bool created=false,bool finalized=false,const char* property="NONE") {
  std::cerr<<"{\"status\":\"STOPPED_DIAGNOSTIC_ONLY\",\"stage\":\""<<stage<<"\",\"detail\":"
           <<static_cast<unsigned long>(code)<<",\"unnamedKeyCreated\":"<<(created?"true":"false")
           <<",\"keyFinalized\":"<<(finalized?"true":"false")<<",\"readProperty\":\""<<property<<"\",\"actionAuthorized\":false}"<<std::endl;
  return 1;
}
int Probe(const std::string& nonceHex) {
  std::vector<unsigned char> nonce;
  if(!tpm_evidence::DecodeNonce(nonceHex,nonce)) return Fail("INPUT",NTE_INVALID_PARAMETER);
  UINT32 device[4]={};
  if(Tbsi_GetDeviceInfo(sizeof(device),device)!=TBS_SUCCESS) return Fail("TPM_INFO",NTE_DEVICE_NOT_FOUND);
  Handle provider;
  SECURITY_STATUS status=NCryptOpenStorageProvider(reinterpret_cast<NCRYPT_PROV_HANDLE*>(&provider.value),MS_PLATFORM_CRYPTO_PROVIDER,0);
  if(status!=ERROR_SUCCESS) return Fail("PROVIDER",status);
  DWORD implementation=0,written=0;
  status=NCryptGetProperty(provider.value,NCRYPT_IMPL_TYPE_PROPERTY,reinterpret_cast<PBYTE>(&implementation),sizeof(implementation),&written,0);
  if(status!=ERROR_SUCCESS||written!=sizeof(implementation)||!(implementation&NCRYPT_IMPL_HARDWARE_FLAG)||(implementation&NCRYPT_IMPL_SOFTWARE_FLAG))
    return Fail("HARDWARE_PROVIDER_ONLY",status==ERROR_SUCCESS?NTE_BAD_PROVIDER:status);
  EphemeralOps ops(static_cast<NCRYPT_PROV_HANDLE>(provider.value));
  const auto step=tpm_evidence::ConfigureEphemeralAik(ops);
  if(step!=tpm_evidence::Step::Configured) return Fail(tpm_evidence::Name(step),ops.status,ops.created,ops.finalized,ops.failedReadProperty);
  DWORD pcrMask=0x00ffffff;
  NCryptBuffer buffers[]={
    {sizeof(pcrMask),NCRYPTBUFFER_TPM_PLATFORM_CLAIM_PCR_MASK,&pcrMask},
    {static_cast<ULONG>(nonce.size()),NCRYPTBUFFER_TPM_PLATFORM_CLAIM_NONCE,nonce.data()}
  };
  NCryptBufferDesc parameters={NCRYPTBUFFER_VERSION,2,buffers};
  DWORD required=0;
  status=NCryptCreateClaim(0,ops.key.value,NCRYPT_CLAIM_PLATFORM,&parameters,nullptr,0,&required,0);
  if(status!=ERROR_SUCCESS||required<24||required>32768) return Fail("CLAIM_SIZE",status==ERROR_SUCCESS?NTE_BAD_DATA:status,true,true);
  std::vector<unsigned char> claim(required);
  status=NCryptCreateClaim(0,ops.key.value,NCRYPT_CLAIM_PLATFORM,&parameters,claim.data(),required,&written,0);
  if(status!=ERROR_SUCCESS||written<24||written>required) return Fail("CLAIM_DATA",status==ERROR_SUCCESS?NTE_BAD_DATA:status,true,true);
  claim.resize(written);
  NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT header={};
  static_assert(sizeof(header)==24,"Expected Windows claim header layout");
  std::memcpy(&header,claim.data(),24);
  const std::size_t total=24ull+header.cbSignature+header.cbQuote+header.cbPcrs;
  if(header.Magic!=0x54504c41||header.Version!=0||header.cbSignature<4||header.cbSignature>1024||header.cbQuote==0||total!=claim.size())
    return Fail("CLAIM_CONTAINER",NTE_BAD_DATA,true,true);
  // Metadata only, not a new TPM verifier: retain all signature/quote bytes for TSS parsing offline.
  const unsigned scheme=(static_cast<unsigned>(claim[24])<<8)|claim[25];
  const unsigned hash=(static_cast<unsigned>(claim[26])<<8)|claim[27];
  required=0;
  status=NCryptExportKey(ops.key.value,0,BCRYPT_RSAPUBLIC_BLOB,nullptr,nullptr,0,&required,0);
  if(status!=ERROR_SUCCESS||required<24||required>1024) return Fail("PUBLIC_SIZE",status==ERROR_SUCCESS?NTE_BAD_DATA:status,true,true);
  std::vector<unsigned char> pub(required);
  status=NCryptExportKey(ops.key.value,0,BCRYPT_RSAPUBLIC_BLOB,nullptr,pub.data(),required,&written,0);
  if(status!=ERROR_SUCCESS||written>required||written<24) return Fail("PUBLIC_DATA",status==ERROR_SUCCESS?NTE_BAD_DATA:status,true,true);
  pub.resize(written);
  std::vector<unsigned char> digest;
  if(!Hash(claim.data(),claim.size(),&digest)) return Fail("CLAIM_HASH",NTE_BAD_HASH,true,true);
  std::cout<<"{\"schemaVersion\":1,\"command\":\"ephemeral-claim\",\"mode\":\"UNNAMED_EPHEMERAL_KEY_DIAGNOSTIC_ONLY\","
           <<"\"provider\":\"Microsoft Platform Crypto Provider\",\"profileSettingsApplied\":true,"
           <<"\"profileReadbackComplete\":"<<(ops.readbackComplete?"true":"false")<<",\"readbacks\":";
  ops.WriteReadbacks(std::cout);
  std::cout<<","
           <<"\"publicKeyBlobHex\":\""<<Hex(pub)<<"\",\"nonceHex\":\""<<Hex(nonce)
           <<"\",\"platformAttestationClaimHex\":\""<<Hex(claim)<<"\",\"platformAttestationClaimSha256\":\""<<Hex(digest)
           <<"\",\"pcrMask\":"<<pcrMask<<",\"observedPcrAlgorithm\":"<<header.pcrAlg
           <<",\"observedSignatureScheme\":"<<scheme<<",\"observedSignatureHash\":"<<hash
           <<",\"bothSha256Metadata\":"<<((header.pcrAlg==0x0b&&scheme==0x14&&hash==0x0b)?"true":"false")
           <<",\"certificatePresent\":false,\"hardwareOriginVerified\":false,\"actionAuthorized\":false}"<<std::endl;
  // Metadata is only a profile check; the output still needs independent crypto verification.
  return (header.pcrAlg==0x0b && scheme==0x14 && hash==0x0b) ? 0 : 2;
}
}  // namespace
int wmain(int argc,wchar_t* argv[]) {
  try {
    if(argc==2 && std::wstring(argv[1])==L"--help") {
      std::cout<<"EphemeralClaim ephemeral-claim --nonce-hex <64 lowercase hex chars> --acknowledge-ephemeral-key\n"
               <<"Creates one unnamed RSA2048 identity key, then requests a platform claim. No enrollment.\n";
      return 0;
    }
    if(argc!=5||std::wstring(argv[1])!=L"ephemeral-claim"||std::wstring(argv[2])!=L"--nonce-hex"||
       std::wstring(argv[4])!=L"--acknowledge-ephemeral-key") return Fail("ARGUMENTS",NTE_INVALID_PARAMETER);
    auto ascii=[](const wchar_t* s){std::string out;for(;*s;++s){if(*s>127)return std::string{};out.push_back(static_cast<char>(*s));}return out;};
    return Probe(ascii(argv[3]));
  } catch(...) { return Fail("EXCEPTION",NTE_FAIL); }
}
