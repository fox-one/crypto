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
	"os"
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

func Load() (result int) {
	result = int(C.Initialize())
	if result != 0 {
		return
	}

	cfcaLicense := os.Getenv("CFCA_LICENSE")
	if cfcaLicense == "" {
		cfcaLicense = "/license/cfca.license"
	}

	var szLicenseFilePath = C.CString(cfcaLicense)
	defer C.free(unsafe.Pointer(szLicenseFilePath))
	result = int(C.ImportLicenseFile(szLicenseFilePath))
	if result != 0 {
		return
	}

	sm.SetupKeyFactory(smFactory{})
	return
}
