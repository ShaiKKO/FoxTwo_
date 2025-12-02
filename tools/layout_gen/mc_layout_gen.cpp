// mc_layout_gen.cpp
// DIA-based layout extractor stub for _IOP_MC_BUFFER_ENTRY
// CLI shape (initial):
//   mc_layout_gen.exe \
//       --image <ntoskrnl.exe> \
//       --pdb <ntkrnlmp.pdb> \
//       --out-header <path> \
//       [--out-json <path>] \
//       [--symbol-name <name>] \
//       [--era <name>] \
//       [--verbose]

#include <dia2.h>
#include <windows.h>
#include <winver.h>

#include <cstdarg>
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

#pragma comment(lib, "diaguids.lib")
#pragma comment(lib, "version.lib")

struct McLayoutOptions {
  std::wstring ImagePath;
  std::wstring PdbPath;
  std::wstring OutHeaderPath;
  std::wstring OutJsonPath;
  std::wstring SymbolName;
  std::wstring EraName;
  bool Verbose;

  McLayoutOptions() : Verbose(false) {
  }
};

struct McLayout {
  ULONG SizeBytes;

  ULONG OffsetType;
  ULONG OffsetReserved;
  ULONG OffsetSize;
  ULONG OffsetReferenceCount;
  ULONG OffsetFlags;
  ULONG OffsetGlobalDataLink;
  ULONG OffsetAddress;
  ULONG OffsetLength;
  ULONG OffsetAccessMode;
  ULONG OffsetMdlRef;
  ULONG OffsetMdl;

  DWORD FileMajor;
  DWORD FileMinor;
  DWORD FileBuild;
  DWORD FileRevision;

  std::wstring EraName;

  McLayout()
      : SizeBytes(0), OffsetType(0), OffsetReserved(0), OffsetSize(0), OffsetReferenceCount(0),
        OffsetFlags(0), OffsetGlobalDataLink(0), OffsetAddress(0), OffsetLength(0),
        OffsetAccessMode(0), OffsetMdlRef(0), OffsetMdl(0), FileMajor(0), FileMinor(0),
        FileBuild(0), FileRevision(0) {
  }
};

static void LogError(const wchar_t *fmt, ...) {
  if (fmt == nullptr) {
    return;
  }

  va_list args;
  va_start(args, fmt);
  std::vfwprintf(stderr, fmt, args);
  std::fputwc(L'\n', stderr);
  va_end(args);
}

static void LogInfoVerbose(const McLayoutOptions &opts, const wchar_t *fmt, ...) {
  if (!opts.Verbose || fmt == nullptr) {
    return;
  }

  va_list args;
  va_start(args, fmt);
  std::vfwprintf(stderr, fmt, args);
  std::fputwc(L'\n', stderr);
  va_end(args);
}

static bool ReadImagePdbSignature(const std::wstring &imagePath, GUID *outGuid, DWORD *outAge) {
  if (outGuid == nullptr || outAge == nullptr) {
    return false;
  }

  HANDLE hFile = CreateFileW(imagePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile == INVALID_HANDLE_VALUE) {
    LogError(L"Failed to open image file: %ls (error=%lu)", imagePath.c_str(), GetLastError());
    return false;
  }

  HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (hMap == nullptr) {
    LogError(L"CreateFileMappingW failed for %ls (error=%lu)", imagePath.c_str(), GetLastError());
    CloseHandle(hFile);
    return false;
  }

  BYTE *base = static_cast<BYTE *>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
  if (base == nullptr) {
    LogError(L"MapViewOfFile failed for %ls (error=%lu)", imagePath.c_str(), GetLastError());
    CloseHandle(hMap);
    CloseHandle(hFile);
    return false;
  }

  bool ok = false;

  __try {
    const IMAGE_DOS_HEADER *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
      LogError(L"Invalid DOS signature in image: %ls", imagePath.c_str());
      __leave;
    }

    const IMAGE_NT_HEADERS64 *nt =
        reinterpret_cast<const IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
      LogError(L"Invalid NT signature in image: %ls", imagePath.c_str());
      __leave;
    }

    const IMAGE_DATA_DIRECTORY &dbgDirData =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (dbgDirData.VirtualAddress == 0 || dbgDirData.Size == 0) {
      LogError(L"Image has no debug directory: %ls", imagePath.c_str());
      __leave;
    }

    const DWORD rva = dbgDirData.VirtualAddress;
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    DWORD fileOffset = 0;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
      const DWORD secVA = sec->VirtualAddress;
      const DWORD secSize = sec->SizeOfRawData;
      if (rva >= secVA && rva < secVA + secSize) {
        fileOffset = sec->PointerToRawData + (rva - secVA);
        break;
      }
    }

    if (fileOffset == 0) {
      LogError(L"Failed to map debug directory RVA for image: %ls", imagePath.c_str());
      __leave;
    }

    const IMAGE_DEBUG_DIRECTORY *dbgDir =
        reinterpret_cast<const IMAGE_DEBUG_DIRECTORY *>(base + fileOffset);
    const DWORD count = dbgDirData.Size / sizeof(IMAGE_DEBUG_DIRECTORY);

    struct CV_INFO_PDB70 {
      DWORD CvSignature;
      GUID Signature;
      DWORD Age;
    };

    const DWORD RSDS = 0x53445352; /* 'RSDS' */

    for (DWORD i = 0; i < count; ++i) {
      const IMAGE_DEBUG_DIRECTORY &entry = dbgDir[i];
      if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
        continue;
      }
      if (entry.PointerToRawData == 0 || entry.SizeOfData < sizeof(CV_INFO_PDB70)) {
        continue;
      }

      const BYTE *cvBase = base + entry.PointerToRawData;
      const CV_INFO_PDB70 *cvInfo = reinterpret_cast<const CV_INFO_PDB70 *>(cvBase);
      if (cvInfo->CvSignature != RSDS) {
        continue;
      }

      *outGuid = cvInfo->Signature;
      *outAge = cvInfo->Age;
      ok = true;
      break;
    }

    if (!ok) {
      LogError(L"No CodeView RSDS record found in image: %ls", imagePath.c_str());
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    LogError(L"Exception while parsing image headers for: %ls", imagePath.c_str());
    ok = false;
  }

  UnmapViewOfFile(base);
  CloseHandle(hMap);
  CloseHandle(hFile);

  return ok;
}

static bool ValidatePdbMatchesImage(const McLayoutOptions &opts, const GUID &pdbGuid,
                                    DWORD pdbAge) {
  GUID imgGuid = {};
  DWORD imgAge = 0;

  if (!ReadImagePdbSignature(opts.ImagePath, &imgGuid, &imgAge)) {
    return false;
  }

  if (!InlineIsEqualGUID(pdbGuid, imgGuid) || pdbAge != imgAge) {
    wchar_t pdbGuidStr[64] = {0};
    wchar_t imgGuidStr[64] = {0};

    if (StringFromGUID2(pdbGuid, pdbGuidStr,
                        static_cast<int>(sizeof(pdbGuidStr) / sizeof(wchar_t))) == 0) {
      pdbGuidStr[0] = L'\0';
    }
    if (StringFromGUID2(imgGuid, imgGuidStr,
                        static_cast<int>(sizeof(imgGuidStr) / sizeof(wchar_t))) == 0) {
      imgGuidStr[0] = L'\0';
    }

    LogError(L"PDB does not match image. PDB GUID=%ls Age=%lu, Image GUID=%ls "
             L"Age=%lu",
             pdbGuidStr, pdbAge, imgGuidStr, imgAge);
    return false;
  }

  return true;
}

static bool ReadImageVersion(const std::wstring &imagePath, DWORD *maj, DWORD *min, DWORD *build,
                             DWORD *rev) {
  if (maj == nullptr || min == nullptr || build == nullptr || rev == nullptr) {
    return false;
  }

  DWORD handle = 0;
  DWORD verSize = GetFileVersionInfoSizeW(imagePath.c_str(), &handle);
  if (verSize == 0) {
    return false;
  }

  std::vector<BYTE> buf(verSize);
  if (!GetFileVersionInfoW(imagePath.c_str(), 0, verSize, buf.data())) {
    return false;
  }

  VS_FIXEDFILEINFO *pFixed = nullptr;
  UINT len = 0;
  if (!VerQueryValueW(buf.data(), L"\\", reinterpret_cast<LPVOID *>(&pFixed), &len)) {
    return false;
  }
  if (pFixed == nullptr) {
    return false;
  }

  *maj = HIWORD(pFixed->dwFileVersionMS);
  *min = LOWORD(pFixed->dwFileVersionMS);
  *build = HIWORD(pFixed->dwFileVersionLS);
  *rev = LOWORD(pFixed->dwFileVersionLS);

  return true;
}

static HRESULT InitializeDiaSession(const McLayoutOptions &opts, IDiaDataSource **ppSource,
                                    IDiaSession **ppSession, IDiaSymbol **ppGlobal, GUID *outGuid,
                                    DWORD *outAge) {
  if (ppSource == nullptr || ppSession == nullptr || ppGlobal == nullptr || outGuid == nullptr ||
      outAge == nullptr) {
    return E_INVALIDARG;
  }

  *ppSource = nullptr;
  *ppSession = nullptr;
  *ppGlobal = nullptr;
  *outGuid = GUID{};
  *outAge = 0;

  IDiaDataSource *source = nullptr;
  IDiaSession *session = nullptr;
  IDiaSymbol *global = nullptr;

  HRESULT hr = CoCreateInstance(CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER, IID_IDiaDataSource,
                                reinterpret_cast<void **>(&source));
  if (FAILED(hr)) {
    LogError(L"CoCreateInstance(CLSID_DiaSource) failed: 0x%08X", hr);
    return hr;
  }

  hr = source->loadDataFromPdb(opts.PdbPath.c_str());
  if (FAILED(hr)) {
    LogError(L"loadDataFromPdb failed for %ls: 0x%08X", opts.PdbPath.c_str(), hr);
    source->Release();
    return hr;
  }

  hr = source->openSession(&session);
  if (FAILED(hr)) {
    LogError(L"openSession failed: 0x%08X", hr);
    source->Release();
    return hr;
  }

  hr = session->get_globalScope(&global);
  if (FAILED(hr)) {
    LogError(L"get_globalScope failed: 0x%08X", hr);
    session->Release();
    source->Release();
    return hr;
  }

  GUID pdbGuid = {};
  DWORD pdbAge = 0;
  if (FAILED(global->get_guid(&pdbGuid))) {
    LogError(L"get_guid failed on global scope symbol");
    global->Release();
    session->Release();
    source->Release();
    return E_FAIL;
  }
  if (FAILED(global->get_age(&pdbAge))) {
    LogError(L"get_age failed on global scope symbol");
    global->Release();
    session->Release();
    source->Release();
    return E_FAIL;
  }

  *ppSource = source;
  *ppSession = session;
  *ppGlobal = global;
  *outGuid = pdbGuid;
  *outAge = pdbAge;

  return S_OK;
}

static bool ExtractFieldOffset(IDiaSymbol *pUdt, const wchar_t *fieldName, ULONG *outOffset) {
  if (pUdt == nullptr || fieldName == nullptr || outOffset == nullptr) {
    return false;
  }

  IDiaEnumSymbols *pEnum = nullptr;
  HRESULT hr = pUdt->findChildren(SymTagData, fieldName, nsCaseInsensitive, &pEnum);
  if (FAILED(hr) || pEnum == nullptr) {
    return false;
  }

  IDiaSymbol *pField = nullptr;
  ULONG fetched = 0;
  hr = pEnum->Next(1, &pField, &fetched);
  pEnum->Release();
  if (FAILED(hr) || fetched == 0 || pField == nullptr) {
    return false;
  }

  LONG offset = 0;
  hr = pField->get_offset(&offset);
  pField->Release();
  if (FAILED(hr)) {
    return false;
  }

  *outOffset = static_cast<ULONG>(offset);
  return true;
}

static bool ExtractMcLayout(IDiaSession *session, IDiaSymbol *global, const McLayoutOptions &opts,
                            McLayout &layout) {
  if (session == nullptr || global == nullptr) {
    return false;
  }

  IDiaEnumSymbols *pEnum = nullptr;
  HRESULT hr = global->findChildren(SymTagUDT, opts.SymbolName.c_str(), nsCaseInsensitive, &pEnum);
  if (FAILED(hr) || pEnum == nullptr) {
    LogError(L"Unable to find UDT '%ls' in PDB", opts.SymbolName.c_str());
    return false;
  }

  IDiaSymbol *pUdt = nullptr;
  ULONG fetched = 0;
  hr = pEnum->Next(1, &pUdt, &fetched);
  pEnum->Release();
  if (FAILED(hr) || fetched == 0 || pUdt == nullptr) {
    LogError(L"UDT '%ls' not found in PDB", opts.SymbolName.c_str());
    return false;
  }

  LONG len = 0;
  hr = pUdt->get_length(&len);
  if (FAILED(hr)) {
    LogError(L"get_length failed for UDT '%ls'", opts.SymbolName.c_str());
    pUdt->Release();
    return false;
  }
  layout.SizeBytes = static_cast<ULONG>(len);

  bool ok = true;

  ok = ok && ExtractFieldOffset(pUdt, L"Type", &layout.OffsetType);
  ok = ok && ExtractFieldOffset(pUdt, L"Reserved", &layout.OffsetReserved);
  ok = ok && ExtractFieldOffset(pUdt, L"Size", &layout.OffsetSize);
  ok = ok && ExtractFieldOffset(pUdt, L"ReferenceCount", &layout.OffsetReferenceCount);
  ok = ok && ExtractFieldOffset(pUdt, L"Flags", &layout.OffsetFlags);
  ok = ok && ExtractFieldOffset(pUdt, L"GlobalDataLink", &layout.OffsetGlobalDataLink);
  ok = ok && ExtractFieldOffset(pUdt, L"Address", &layout.OffsetAddress);
  ok = ok && ExtractFieldOffset(pUdt, L"Length", &layout.OffsetLength);
  ok = ok && ExtractFieldOffset(pUdt, L"AccessMode", &layout.OffsetAccessMode);
  ok = ok && ExtractFieldOffset(pUdt, L"MdlRef", &layout.OffsetMdlRef);
  ok = ok && ExtractFieldOffset(pUdt, L"Mdl", &layout.OffsetMdl);

  pUdt->Release();

  if (!ok) {
    LogError(L"Failed to resolve all required field offsets for '%ls'", opts.SymbolName.c_str());
  }

  return ok;
}

static bool WriteHeader(const McLayoutOptions &opts, const McLayout &layout) {
  FILE *f = _wfopen(opts.OutHeaderPath.c_str(), L"w, ccs=UTF-8");
  if (f == nullptr) {
    LogError(L"Failed to open header output file: %ls", opts.OutHeaderPath.c_str());
    return false;
  }

  std::fwprintf(f, L"#pragma once\n\n");
  std::fwprintf(f, L"/* Autogenerated by mc_layout_gen; do not edit by hand. */\n\n");

  std::fwprintf(f, L"#define IOP_MC_LAYOUT_BUILD_MAJOR        %lu\n",
                static_cast<unsigned long>(layout.FileMajor));
  std::fwprintf(f, L"#define IOP_MC_LAYOUT_BUILD_MINOR        %lu\n",
                static_cast<unsigned long>(layout.FileMinor));
  std::fwprintf(f, L"#define IOP_MC_LAYOUT_BUILD_NUMBER       %lu\n",
                static_cast<unsigned long>(layout.FileBuild));
  std::fwprintf(f, L"#define IOP_MC_LAYOUT_BUILD_REVISION     %lu\n\n",
                static_cast<unsigned long>(layout.FileRevision));

  const std::wstring &era = layout.EraName.empty() ? std::wstring(L"UNKNOWN_ERA") : layout.EraName;
  std::fwprintf(f, L"#define IOP_MC_LAYOUT_ERA                \"%ls\"\n\n", era.c_str());

  std::fwprintf(f, L"#define IOP_MC_BUFFER_ENTRY_SIZE         0x%Xu\n\n", layout.SizeBytes);

  std::fwprintf(f, L"#define IOP_MC_FIELD_TYPE_OFFSET               0x%Xu\n", layout.OffsetType);
  std::fwprintf(f, L"#define IOP_MC_FIELD_RESERVED_OFFSET           0x%Xu\n",
                layout.OffsetReserved);
  std::fwprintf(f, L"#define IOP_MC_FIELD_SIZE_OFFSET               0x%Xu\n", layout.OffsetSize);
  std::fwprintf(f, L"#define IOP_MC_FIELD_REFERENCECOUNT_OFFSET     0x%Xu\n",
                layout.OffsetReferenceCount);
  std::fwprintf(f, L"#define IOP_MC_FIELD_FLAGS_OFFSET              0x%Xu\n", layout.OffsetFlags);
  std::fwprintf(f, L"#define IOP_MC_FIELD_GLOBALDATALINK_OFFSET     0x%Xu\n",
                layout.OffsetGlobalDataLink);
  std::fwprintf(f, L"#define IOP_MC_FIELD_ADDRESS_OFFSET            0x%Xu\n", layout.OffsetAddress);
  std::fwprintf(f, L"#define IOP_MC_FIELD_LENGTH_OFFSET             0x%Xu\n", layout.OffsetLength);
  std::fwprintf(f, L"#define IOP_MC_FIELD_ACCESSMODE_OFFSET         0x%Xu\n",
                layout.OffsetAccessMode);
  std::fwprintf(f, L"#define IOP_MC_FIELD_MDLREF_OFFSET             0x%Xu\n", layout.OffsetMdlRef);
  std::fwprintf(f, L"#define IOP_MC_FIELD_MDL_OFFSET                0x%Xu\n", layout.OffsetMdl);

  std::fclose(f);
  return true;
}

static bool WriteJson(const McLayoutOptions &opts, const McLayout &layout) {
  FILE *f = _wfopen(opts.OutJsonPath.c_str(), L"w, ccs=UTF-8");
  if (f == nullptr) {
    LogError(L"Failed to open JSON output file: %ls", opts.OutJsonPath.c_str());
    return false;
  }

  const std::wstring &era = layout.EraName.empty() ? std::wstring(L"UNKNOWN_ERA") : layout.EraName;

  std::fwprintf(f, L"{\n");
  std::fwprintf(f, L"  \"structure\": \"_IOP_MC_BUFFER_ENTRY\",\n");
  std::fwprintf(f,
                L"  \"build\": { \"major\": %lu, \"minor\": %lu, \"number\": "
                L"%lu, \"revision\": %lu },\n",
                static_cast<unsigned long>(layout.FileMajor),
                static_cast<unsigned long>(layout.FileMinor),
                static_cast<unsigned long>(layout.FileBuild),
                static_cast<unsigned long>(layout.FileRevision));
  std::fwprintf(f, L"  \"layoutEra\": \"%ls\",\n", era.c_str());
  std::fwprintf(f, L"  \"size\": %lu,\n", static_cast<unsigned long>(layout.SizeBytes));
  std::fwprintf(f, L"  \"fields\": [\n");

  std::fwprintf(f, L"    { \"name\": \"Type\",           \"offset\": %lu },\n",
                static_cast<unsigned long>(layout.OffsetType));
  std::fwprintf(f, L"    { \"name\": \"Reserved\",       \"offset\": %lu },\n",
                static_cast<unsigned long>(layout.OffsetReserved));
  std::fwprintf(f, L"    { \"name\": \"Size\",           \"offset\": %lu },\n",
                static_cast<unsigned long>(layout.OffsetSize));
  std::fwprintf(f, L"    { \"name\": \"ReferenceCount\", \"offset\": %lu },\n",
                static_cast<unsigned long>(layout.OffsetReferenceCount));
  std::fwprintf(f, L"    { \"name\": \"Flags\",          \"offset\": %lu },\n",
                static_cast<unsigned long>(layout.OffsetFlags));
  std::fwprintf(f, L"    { \"name\": \"GlobalDataLink\", \"offset\": %lu },\n",
                static_cast<unsigned long>(layout.OffsetGlobalDataLink));
  std::fwprintf(f, L"    { \"name\": \"Address\",        \"offset\": %lu },\n",
                static_cast<unsigned long>(layout.OffsetAddress));
  std::fwprintf(f, L"    { \"name\": \"Length\",         \"offset\": %lu },\n",
                static_cast<unsigned long>(layout.OffsetLength));
  std::fwprintf(f, L"    { \"name\": \"AccessMode\",     \"offset\": %lu },\n",
                static_cast<unsigned long>(layout.OffsetAccessMode));
  std::fwprintf(f, L"    { \"name\": \"MdlRef\",         \"offset\": %lu },\n",
                static_cast<unsigned long>(layout.OffsetMdlRef));
  std::fwprintf(f, L"    { \"name\": \"Mdl\",            \"offset\": %lu }\n",
                static_cast<unsigned long>(layout.OffsetMdl));

  std::fwprintf(f, L"  ]\n");
  std::fwprintf(f, L"}\n");

  std::fclose(f);
  return true;
}

static void PrintUsage() {
  std::fwprintf(stderr, L"Usage: mc_layout_gen.exe --image <ntoskrnl.exe> --pdb <ntkrnlmp.pdb> "
                        L"--out-header <path> [options]\n"
                        L"Options:\n"
                        L"  --out-json <path>       Optional JSON metadata output\n"
                        L"  --symbol-name <name>    Target UDT name (default: "
                        L"_IOP_MC_BUFFER_ENTRY)\n"
                        L"  --era <name>            Layout era label (e.g. WIN11_ERA_226XX)\n"
                        L"  --verbose               Enable verbose logging to stderr\n");
}

static bool ParseArguments(int argc, wchar_t **argv, McLayoutOptions &opts) {
  for (int i = 1; i < argc; ++i) {
    const wchar_t *arg = argv[i];

    if (_wcsicmp(arg, L"--verbose") == 0) {
      opts.Verbose = true;
      continue;
    }

    if ((i + 1) >= argc) {
      std::fwprintf(stderr, L"Missing value for argument: %ls\n", arg);
      return false;
    }

    const wchar_t *val = argv[++i];

    if (_wcsicmp(arg, L"--image") == 0) {
      opts.ImagePath = val;
    } else if (_wcsicmp(arg, L"--pdb") == 0) {
      opts.PdbPath = val;
    } else if (_wcsicmp(arg, L"--out-header") == 0) {
      opts.OutHeaderPath = val;
    } else if (_wcsicmp(arg, L"--out-json") == 0) {
      opts.OutJsonPath = val;
    } else if (_wcsicmp(arg, L"--symbol-name") == 0) {
      opts.SymbolName = val;
    } else if (_wcsicmp(arg, L"--era") == 0) {
      opts.EraName = val;
    } else {
      std::fwprintf(stderr, L"Unknown argument: %ls\n", arg);
      return false;
    }
  }

  if (opts.SymbolName.empty()) {
    opts.SymbolName = L"_IOP_MC_BUFFER_ENTRY";
  }

  if (opts.ImagePath.empty() || opts.PdbPath.empty() || opts.OutHeaderPath.empty()) {
    std::fwprintf(stderr, L"Missing required arguments.\n");
    return false;
  }

  return true;
}

static int RunExtractor(const McLayoutOptions &opts) {
  HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  bool comInitialized = false;

  if (SUCCEEDED(hr)) {
    comInitialized = true;
  } else if (hr == RPC_E_CHANGED_MODE) {
    // COM already initialized in a different mode; proceed without owning
    // lifetime.
  } else {
    LogError(L"CoInitializeEx failed: 0x%08X", hr);
    return ERROR_INVALID_PARAMETER;
  }

  IDiaDataSource *source = nullptr;
  IDiaSession *session = nullptr;
  IDiaSymbol *global = nullptr;
  GUID pdbGuid = {};
  DWORD pdbAge = 0;

  hr = InitializeDiaSession(opts, &source, &session, &global, &pdbGuid, &pdbAge);
  if (FAILED(hr)) {
    if (comInitialized) {
      CoUninitialize();
    }
    return ERROR_INVALID_DATA;
  }

  if (!ValidatePdbMatchesImage(opts, pdbGuid, pdbAge)) {
    if (global)
      global->Release();
    if (session)
      session->Release();
    if (source)
      source->Release();
    if (comInitialized) {
      CoUninitialize();
    }
    return ERROR_INVALID_DATA;
  }

  McLayout layout;
  layout.EraName = opts.EraName;

  if (!ExtractMcLayout(session, global, opts, layout)) {
    if (global)
      global->Release();
    if (session)
      session->Release();
    if (source)
      source->Release();
    if (comInitialized) {
      CoUninitialize();
    }
    return ERROR_INVALID_DATA;
  }

  if (!ReadImageVersion(opts.ImagePath, &layout.FileMajor, &layout.FileMinor, &layout.FileBuild,
                        &layout.FileRevision)) {
    LogInfoVerbose(opts, L"Warning: unable to read image version metadata from %ls",
                   opts.ImagePath.c_str());
  }

  if (!WriteHeader(opts, layout)) {
    if (global)
      global->Release();
    if (session)
      session->Release();
    if (source)
      source->Release();
    if (comInitialized) {
      CoUninitialize();
    }
    return ERROR_WRITE_FAULT;
  }

  if (!opts.OutJsonPath.empty()) {
    if (!WriteJson(opts, layout)) {
      if (global)
        global->Release();
      if (session)
        session->Release();
      if (source)
        source->Release();
      if (comInitialized) {
        CoUninitialize();
      }
      return ERROR_WRITE_FAULT;
    }
  }

  if (global)
    global->Release();
  if (session)
    session->Release();
  if (source)
    source->Release();
  if (comInitialized) {
    CoUninitialize();
  }

  LogInfoVerbose(opts, L"[mc_layout_gen] Successfully generated layout header.");
  return 0;
}

int wmain(int argc, wchar_t **argv) {
  McLayoutOptions opts;

  if (argc <= 1) {
    PrintUsage();
    return ERROR_INVALID_PARAMETER;
  }

  if (!ParseArguments(argc, argv, opts)) {
    PrintUsage();
    return ERROR_INVALID_PARAMETER;
  }

  return RunExtractor(opts);
}
