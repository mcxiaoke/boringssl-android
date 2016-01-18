#!/usr/bin/env bash
ndk-build NDK_PROJECT_PATH=. NDK_APPLICATION_MK=Application.mk APP_MODULES=crypto_static $@

