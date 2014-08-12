#if defined(WIN32)
#   include <windows.h>
#   include <tchar.h>
# define LOAD_LIBRARY(libName)              LoadLibrary(_T(libName))
# define GET_FUNCTION(hModule, funcName)    GetProcAddress((HMODULE) hModule, #funcName)
# define FREE_LIBRARY(hModule)              FreeLibrary((HMODULE) hModule)
#elif defined(__APPLE__) && (TARGET_OS_IPHONE == 1)
# include <TargetConditionals.h>
# define LOAD_LIBRARY(libName)              1
# define GET_FUNCTION(hModule, funcName)    funcName
# define FREE_LIBRARY(hModule)
#else
# include <dlfcn.h>
# define LOAD_LIBRARY(libName)              dlopen(libName, RTLD_LAZY)
# define GET_FUNCTION(hModule, funcName)    dlsym(hModule, #funcName)
# define FREE_LIBRARY(hModule)              dlclose(hModule)
#endif
