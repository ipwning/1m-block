all: 1m_block

1m_block: 1m_block.o main.o
	g++ -o 1m_block 1m_block.o main.o -lnetfilter_queue -lpthread

main.o: header.h 1m_block.h main.cpp 

1m_block.o: header.h 1m_block.h 1m_block.cpp

clean:
	rm -f 1m_block
	rm -f *.o
