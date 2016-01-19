gloox_libnice : gloox_libnice.cpp
	g++ -std=c++11 -g -O0 gloox_libnice.cpp `pkg-config --cflags nice gloox` -o gloox_libnice `pkg-config --libs nice gloox`

