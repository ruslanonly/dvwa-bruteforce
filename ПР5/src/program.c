#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]){
	FILE *secret = fopen("/challenge/app-systeme/ch5/.passwd", "rt");
	char buffer[32];
	fgets(buffer, sizeof(buffer), secret);
	printf(argv[1]);
	fclose(secret);
	return 0;
}