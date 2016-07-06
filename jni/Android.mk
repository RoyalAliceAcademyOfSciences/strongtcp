#LOCAL_PATH is used to locate source files in the development tree.
#the macro my-dir provided by the build system, indicates the path of the current directory
LOCAL_PATH:=$(call my-dir)
 
#####################################################################
#			build libnflink					#
#####################################################################
include $(CLEAR_VARS)
LOCAL_MODULE:=nflink
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libnfnetlink/include
LOCAL_SRC_FILES := libnfnetlink/src/iftable.c \
libnfnetlink/src/rtnl.c \
libnfnetlink/src/libnfnetlink.c
include $(BUILD_STATIC_LIBRARY)
#include $(BUILD_SHARED_LIBRARY)
 
#####################################################################
#			build libnetfilter_queue			#
#####################################################################
include $(CLEAR_VARS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libnfnetlink/include \
$(LOCAL_PATH)/libnetfilter_queue/include
LOCAL_MODULE:=netfilter_queue
LOCAL_SRC_FILES:=libnetfilter_queue/src/libnetfilter_queue.c
LOCAL_STATIC_LIBRARIES:=libnflink
include $(BUILD_STATIC_LIBRARY)
#include $(BUILD_SHARED_LIBRARY)
 
#####################################################################
#			build our code					#
#####################################################################
include $(CLEAR_VARS)

# Enable PIE manually. Will get reset on $(CLEAR_VARS). This
# is what enabling PIE translates to behind the scenes.
LOCAL_CFLAGS += -fPIE
LOCAL_LDFLAGS += -fPIE -pie

LOCAL_C_INCLUDES := $(LOCAL_PATH)/libnfnetlink/include \
$(LOCAL_PATH)/libnetfilter_queue/include
LOCAL_MODULE:=strongtcp
LOCAL_SRC_FILES:=../src/strongtcp.c \
../src/pcap.h \
../src/pcap.c
LOCAL_STATIC_LIBRARIES:=libnetfilter_queue
LOCAL_LDLIBS:=-llog -lm
#include $(BUILD_SHARED_LIBRARY)
include $(BUILD_EXECUTABLE)
