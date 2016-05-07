LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := inject
LOCAL_SRC_FILES := HookInject.cpp
LOCAL_LDLIBS += -llog
LOCAL_ARM_MODE := arm

include $(BUILD_EXECUTABLE)
