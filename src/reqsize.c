#include <stdio.h>
#include <stdlib.h>

#define ZONEDATA "zonedata.txt"
#define MAXBUF 1024

int
count_lines() {
	FILE *file = fopen(ZONEDATA, "r");

	if (file == NULL)
		return -1;

	char line[MAXBUF];

	// Skip a line
	if (fgets(line, sizeof(line), file) == NULL)
		return -1;

	int linecount = 0;
	while(fgets(line, sizeof(line), file) != NULL) {
		linecount++;
	}
	printf("Line count: %d\n", linecount);
	return linecount;
}

int
get_zonedata(char** zones, int linecount) {
	FILE *file = fopen(ZONEDATA, "r");

	if (file == NULL)
		return -1;

	char line[MAXBUF];

	// Skip a line
	if (fgets(line, sizeof(line), file) == NULL)
		return -1;

	char str[MAXBUF];
	int z = 0;
	for(int i = 0; i < linecount; i++) {
		fscanf(file, "%s", str);
		if ((z == 0) || (strcmp(zones[z-1], str) != 0)) {
			zones[z] = malloc(sizeof(str));
			memcpy(zones[z], str, sizeof(str));
			z++;
		}
		fgets(line, sizeof(line), file);
	}
	printf("Final line count: %d\n", z);
	return z;
}

int main(void) {
	int linecount = count_lines();
	char** zones = malloc(sizeof(char*)*linecount);
	linecount = get_zonedata(zones, linecount);

	for(int i = 0; i < linecount; i++) {
		free(zones[i]);
	}
	free(zones);
	return 0;
}
