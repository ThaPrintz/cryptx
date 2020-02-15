// cryptx.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "cryptx.h"


// This is an example of an exported variable
CRYPTX_API int ncryptx=0;

// This is an example of an exported function.
CRYPTX_API int fncryptx(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
Ccryptx::Ccryptx()
{
    return;
}
