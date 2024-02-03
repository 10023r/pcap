
TARGET = program1
LIBS = -lpcap

$(TARGET) : Sniffer.o main.o 
	g++ main.o Sniffer.o FileSniffer.h DevSniffer.h FileWriter.h -o $(TARGET) $(LIBS)

Sniffer.o : Sniffer.cpp
	g++ -c Sniffer.cpp -o Sniffer.o

main.o : main.cpp
	g++ -c main.cpp -o main.o

clean : 
	rm $(TARGET) *.o *.csv



