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
)

func (f smFactory) Sm3Sum(message []byte) (digest [32]byte) {
	var pbySM3Hash = (*C.uchar)(nil)
	var nSM3Hash = C.int(0)

	result := int(C.SM3HashData((*C.uchar)(unsafe.Pointer(&message[0])), C.int(len(message)),
		&pbySM3Hash, &nSM3Hash))
	defer C.FreeMemory(unsafe.Pointer(pbySM3Hash))
	if result != 0 {
		panic(fmt.Errorf("SM3HashData failed:Error code[0x%8x].", result))
	}

	digest = *new([32]byte)
	copy(digest[:], C.GoBytes(unsafe.Pointer(pbySM3Hash), nSM3Hash))
	return
}
