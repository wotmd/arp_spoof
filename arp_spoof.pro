TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += \
        main.cpp \
        packet.cpp \
        send_arp.cpp

HEADERS += \
    packet.h \
    send_arp.h
