all: scanner part2 part3

scanner: scanner.cpp
	g++ -Wall -std=c++11 scanner.cpp -o scanner

part2: part2.cpp
	g++ -Wall -std=c++11 part2.cpp -o part2

part3: part3.cpp
	g++ -Wall -std=c++11 part3.cpp -o part3


clean:
	rm  scanner
	rm part2
	rm part3