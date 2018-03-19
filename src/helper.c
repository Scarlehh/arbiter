#include "helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAXBUF 1024
#define DELIM "="

void
get_config(char *filename, struct dbconfig* configstruct)
{
	FILE *file = fopen(filename, "r");

	if (file != NULL) {
		char line[MAXBUF];

		while(fgets(line, sizeof(line), file) != NULL) {
			char *cfline;
			cfline = strstr((char *)line,DELIM);
			cfline = cfline + strlen(DELIM);
			if(strlen(cfline) && isspace(cfline[strlen(cfline)-1])) {
				cfline[strlen(cfline)-1] = '\0';
			}

			int length = strlen(cfline)+1;
			if (strncmp(line, "username", 8) == 0) {
				configstruct->username = malloc(sizeof(char)*length);
				memcpy(configstruct->username, cfline, length);
			} else if (strncmp(line, "password", 8) == 0) {
				configstruct->password = malloc(sizeof(char)*length);
				memcpy(configstruct->password, cfline, length);
			} else if (strncmp(line, "dbname", 6) == 0) {
				configstruct->dbname = malloc(sizeof(char)*length);
				memcpy(configstruct->dbname, cfline, length);
			}
		}
		fclose(file);
	}
}
