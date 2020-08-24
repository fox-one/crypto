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

var CfcaLoadResult = -1

func RequestLicense() error {
	// Initialize
	result := int(C.Initialize())
	defer C.Uninitialize()
	if result != 0 {
		return fmt.Errorf("Initialize failed:Error code[0x%8x].", result)
	}

	cfcaRequestPath := os.Getenv("CFCA_REQUEST_PATH")
	if cfcaRequestPath == "" {
		cfcaRequestPath = "/cfca/cfca.activation"
	}
	// Create activation request
	var szActivationFilePath = C.CString(cfcaRequestPath)
	defer C.free(unsafe.Pointer(szActivationFilePath))
	if result = int(C.GenerateActivationRequset(szActivationFilePath)); result != 0 {
		return fmt.Errorf("GenerateActivationRequset failed:Error code[0x%8x].", result)
	}
	return nil
}

func Load() (result int) {
	if CfcaLoadResult == 0 {
		return
	}
	defer CfcaLoadResult = result

	result = int(C.Initialize())
	if result != 0 {
		return
	}

	cfcaLicense := os.Getenv("CFCA_LICENSE")
	if cfcaLicense == "" {
		cfcaLicense = "/cfca/cfca.license"
	}

	var szLicenseFilePath = C.CString(cfcaLicense)
	defer C.free(unsafe.Pointer(szLicenseFilePath))
	result = int(C.ImportLicenseFile(szLicenseFilePath))
	if result != 0 {
		RequestLicense()
		return
	}

	sm.SetupKeyFactory(smFactory{})
	return
}
