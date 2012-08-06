#include <eCardTypes.h>
#include <eCardStatus.h>
#include <vector>

#if !defined(__ECARDCORE_INCLUDED__)
#define __ECARDCORE_INCLUDED__

#if defined(WIN32) || defined(WINCE)// Windows related stuff
#   if defined(ECARD_EXPORTS)
#       define ECARD_API __declspec(dllexport)
#   else
#       define ECARD_API __declspec(dllimport)
#   endif
#   define __STDCALL__ __stdcall
#else // Linux related stuff
#   define ECARD_API
#   define __STDCALL__
#endif

#endif
