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

int
get_mysql_cert(char* configfile, char* domain, char** cert, int ksk);

#endif
