TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.cpp

INCLUDEPATH += /root/boost
LIBS += -L/root/boost/stage/lib -lboost_system -lpcap -pthread
