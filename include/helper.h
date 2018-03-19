#ifndef HELPER_H
#define HELPER_H

struct dbconfig
{
	char* username;
	char* password;
	char* dbname;
};

void
get_config(char *filename, struct dbconfig* configstruct);

#endif
