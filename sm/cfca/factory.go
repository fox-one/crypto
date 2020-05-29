package cfca

/*
#cgo CFLAGS: -I./
#cgo LDFLAGS: -lstdc++ -ldl -L./ -lSADK_CNERT
#include <stdlib.h>
#include <dlfcn.h>
#include "SADK.h"
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/fox-one/crypto/sm"
)

type smFactory struct{}

func RequestLicense() error {
	// Initialize
	result := int(C.Initialize())
	defer C.Uninitialize()
	if result != 0 {
		return fmt.Errorf("Initialize failed:Error code[0x%8x].", result)
	}

	// Create activation request
	var szActivationFilePath = C.CString("./cfca.activation")
	defer C.free(unsafe.Pointer(szActivationFilePath))
	if result = int(C.GenerateActivationRequset(szActivationFilePath)); result != 0 {
		return fmt.Errorf("GenerateActivationRequset failed:Error code[0x%8x].", result)
	}
	return nil
}

func Load(licensePath string) (result int) {
	result = int(C.Initialize())
	if result != 0 {
		return
	}

	var szLicenseFilePath = C.CString(licensePath)
	defer C.free(unsafe.Pointer(szLicenseFilePath))
	result = int(C.ImportLicenseFile(szLicenseFilePath))
	if result != 0 {
		return
	}

	sm.SetupKeyFactory(smFactory{})
	return
}
