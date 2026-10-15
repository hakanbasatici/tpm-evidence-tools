#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tbs.h>
#include <array>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#pragma comment(lib,"tbs.lib")
namespace {
// Microsoft TSS.NET GetCapabilities sample: Cap.Pcrs, property=0, propertyCount=255.
constexpr std::array<BYTE,22> kCommand={
  0x80,0x01,0x00,0x00,0x00,0x16,0x00,0x00,0x01,0x7a,
  0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff
};
std::string Hex(const BYTE* data,std::size_t size) {
  std::ostringstream out;out<<std::hex<<std::setfill('0');
  for(std::size_t i=0;i<size;++i)out<<std::setw(2)<<static_cast<unsigned>(data[i]);
  return out.str();
}
class Context {
 public:
  TBS_HCONTEXT handle=0;
  Context()=default;
  Context(const Context&)=delete;
  Context& operator=(const Context&)=delete;
  ~Context(){if(handle)Tbsip_Context_Close(handle);}
};
int Fail(const char* stage,UINT32 detail) {
  std::cerr<<"{\"status\":\"PCR_CAPABILITY_DIAGNOSTIC_FAILED\",\"stage\":\""<<stage
           <<"\",\"detail\":"<<detail<<",\"actionAuthorized\":false}"<<std::endl;
  return 1;
}
int Query() {
  TBS_CONTEXT_PARAMS2 parameters={};
  parameters.version=TBS_CONTEXT_VERSION_TWO;parameters.includeTpm20=1;
  Context context;
  TBS_RESULT status=Tbsi_Context_Create(reinterpret_cast<const TBS_CONTEXT_PARAMS*>(&parameters),&context.handle);
  if(status!=TBS_SUCCESS)return Fail("CONTEXT_CREATE",status);
  std::array<BYTE,4096> response={};UINT32 length=static_cast<UINT32>(response.size());
  // Fixed allowlisted read-only command; no external raw command argument exists.
  status=Tbsip_Submit_Command(context.handle,TBS_COMMAND_LOCALITY_ZERO,TBS_COMMAND_PRIORITY_NORMAL,
                             kCommand.data(),static_cast<UINT32>(kCommand.size()),response.data(),&length);
  if(status!=TBS_SUCCESS)return Fail("SUBMIT_READONLY_CAPABILITY",status);
  if(length<10||length>response.size())return Fail("RESPONSE_SIZE",length);
  // Preserve all response bytes; decode the TPM structure using pinned TSS.Py offline.
  std::cout<<"{\"schemaVersion\":1,\"command\":\"pcr-banks\",\"mode\":\"READONLY_CAPABILITY_ONLY\","
           <<"\"requestHex\":\""<<Hex(kCommand.data(),kCommand.size())<<"\",\"responseHex\":\""
           <<Hex(response.data(),length)<<"\",\"submitCalls\":1,\"keyCreates\":0,\"pcrWrites\":0,"
           <<"\"hardwareOriginVerified\":false,\"actionAuthorized\":false}"<<std::endl;
  return 0;
}
}
int wmain(int argc,wchar_t* argv[]) {
  if(argc==2 && std::wstring(argv[1])==L"--help") {
    std::cout<<"PcrBanks pcr-banks --acknowledge-readonly-query\nOne fixed TPM2_GetCapability/PCRS query. No key or PCR write.\n";
    return 0;
  }
  if(argc!=3||std::wstring(argv[1])!=L"pcr-banks"||std::wstring(argv[2])!=L"--acknowledge-readonly-query")return Fail("ARGUMENTS",0);
  try{return Query();}catch(...){return Fail("EXCEPTION",0);}
}
