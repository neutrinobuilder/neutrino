// Copyright (C) 2026 Neutrino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//go:build android

// Package androidnative resolves Android-specific paths (currently just
// nativeLibraryDir), used by internal/tornode and internal/i2pnode to
// locate the binaries shipped inside the APK.
package androidnative

/*
#include <jni.h>
#include <stdlib.h>
#include <string.h>

// Calls Context.getApplicationInfo() -> ApplicationInfo.nativeLibraryDir
// (public SDK API, no reflection/hidden API) via raw JNI. Returns a
// string allocated with strdup (the caller must C.free it) or NULL with
// *errOut set (also to be C.free'd).
static char *nativeLibraryDirFromContext(uintptr_t jniEnv, uintptr_t ctxObj, char **errOut) {
    JNIEnv *env = (JNIEnv *)jniEnv;
    jobject context = (jobject)ctxObj;
    *errOut = NULL;

    jclass contextClass = (*env)->GetObjectClass(env, context);
    if (contextClass == NULL) { *errOut = strdup("GetObjectClass(context) failed"); return NULL; }

    jmethodID getAppInfo = (*env)->GetMethodID(env, contextClass,
        "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    if (getAppInfo == NULL) {
        (*env)->ExceptionClear(env);
        *errOut = strdup("GetMethodID(getApplicationInfo) failed"); return NULL;
    }

    jobject appInfo = (*env)->CallObjectMethod(env, context, getAppInfo);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        *errOut = strdup("CallObjectMethod(getApplicationInfo) threw"); return NULL;
    }

    jclass appInfoClass = (*env)->GetObjectClass(env, appInfo);
    jfieldID field = (*env)->GetFieldID(env, appInfoClass, "nativeLibraryDir", "Ljava/lang/String;");
    if (field == NULL) {
        (*env)->ExceptionClear(env);
        *errOut = strdup("GetFieldID(nativeLibraryDir) failed"); return NULL;
    }

    jstring jpath = (jstring)(*env)->GetObjectField(env, appInfo, field);
    if (jpath == NULL) { *errOut = strdup("nativeLibraryDir field is null"); return NULL; }

    const char *utf = (*env)->GetStringUTFChars(env, jpath, NULL);
    char *result = strdup(utf);
    (*env)->ReleaseStringUTFChars(env, jpath, utf);
    return result;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"

	"fyne.io/fyne/v2/driver"
)

// nativeLibraryDirViaJNI uses driver.RunNative (Fyne, android build tag) to
// get the raw VM/Env/Ctx of the same android.content.Context a Java/Kotlin
// app would receive, then calls getApplicationInfo() via cgo, no
// hand-written .java/.kt file. RunNative internally delegates to
// golang.org/x/mobile/internal/mobileinit.RunOnJVM, which already does
// runtime.LockOSThread + JNI thread attach/detach: no need to repeat it
// here.
func nativeLibraryDirViaJNI() (string, error) {
	var result string
	err := driver.RunNative(func(ctxIface any) error {
		ctx, ok := ctxIface.(*driver.AndroidContext)
		if !ok {
			return fmt.Errorf("androidnative: unexpected native context type %T", ctxIface)
		}
		var cerr *C.char
		cpath := C.nativeLibraryDirFromContext(C.uintptr_t(ctx.Env), C.uintptr_t(ctx.Ctx), &cerr)
		if cpath == nil {
			msg := "unknown JNI error"
			if cerr != nil {
				msg = C.GoString(cerr)
				C.free(unsafe.Pointer(cerr))
			}
			return errors.New("androidnative: " + msg)
		}
		defer C.free(unsafe.Pointer(cpath))
		result = C.GoString(cpath)
		return nil
	})
	return result, err
}
