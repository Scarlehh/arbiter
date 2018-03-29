#include "helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <mysql/mysql.h>

#include <ldns/ldns.h>

#define MAXBUF 1024
#define DELIM "="

extern verbosity;

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

int
get_mysql_cert(char* configfile, char* domain, char** cert, int ksk) {
	MYSQL* con = mysql_init(NULL);
	if (con == NULL) {
		fprintf(stderr, "mysql_init() failed\n");
		return LDNS_STATUS_ERR;
	}

	int result;
	struct dbconfig config;
	get_config(configfile, &config);

	if (mysql_real_connect(con, "localhost", config.username, config.password,
						   config.dbname, 0, NULL, 0) == NULL) {
		fprintf(stderr, "%s\n", mysql_error(con));
		result = LDNS_STATUS_ERR;
		goto finish;
	}

	char query[MAXBUF];
	sprintf(query, "SELECT cert FROM certificates WHERE domain='%s' AND ksk=%d", domain, ksk);
	if (mysql_query(con, query)) {
		fprintf(stderr, "%s\n", mysql_error(con));
		result = LDNS_STATUS_ERR;
		goto finish;
	}

	MYSQL_RES* mysql_result = mysql_store_result(con);
	if (mysql_result == NULL) {
		fprintf(stderr, "%s\n", mysql_error(con));
		result = LDNS_STATUS_ERR;
		goto finish;
	}

	MYSQL_ROW row = mysql_fetch_row(mysql_result);
	if (row == 0) {
		if (verbosity >= 2)
			fprintf(stderr, "Domain %s %s is not registered in database\n",
					domain, (ksk ? "KSK" : "ZSK"));
		result = LDNS_STATUS_ERR;
		goto finish;
	} else if (row[0] == NULL) {
		result = LDNS_STATUS_OK;
		*cert = NULL;
		goto finish;
	}

	*cert = malloc(sizeof(char)*(strlen(row[0])+1));
	strncpy(*cert, *row, strlen(row[0])+1);
	mysql_free_result(mysql_result);
	result = LDNS_STATUS_OK;

 finish:
	mysql_close(con);
	free(config.username);
	free(config.password);
	free(config.dbname);
	return result;
}
