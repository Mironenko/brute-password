CXXFLAGS=-I/usr/local/include/ -std=c++1y
LDFLAGS=-lc++ -lcrypto
HEADERS=brute.h utils.h crypto.h
SOURCES=main.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=bruter

all: $(SOURCES) $(EXECUTABLE)

clean: 
	rm *.o $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@