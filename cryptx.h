// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the CRYPTX_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// CRYPTX_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef CRYPTX_EXPORTS
#define CRYPTX_API __declspec(dllexport)
#else
#define CRYPTX_API __declspec(dllimport)
#endif

// This class is exported from the dll
class CRYPTX_API Ccryptx {
public:
	Ccryptx(void);
	// TODO: add your methods here.
};

extern CRYPTX_API int ncryptx;

CRYPTX_API int fncryptx(void);
