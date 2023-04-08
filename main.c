#include "httpd.h"
#include <sys/stat.h>
#include <syslog.h>
#include<stdio.h>
#define CHUNK_SIZE 1024 // read 1024 bytes at a time

// Public directory settings
char * PublicDir;
char * LogDirectory;
FILE* LogFile;
#define INDEX_HTML "/index.html"
#define NOT_FOUND_HTML "/404.html"
#define AUTH_DATA "auth.html"

int main(int c, char **v) {
  char *port = c <= 1 ? "8000" : v[1];
  PublicDir = c <=2 ? "./webroot" : v[2];
  LogDirectory = c <=3 ? "./PicoLog.txt" : v[3];
  LogFile = fopen(LogDirectory, "a");
  syslog (LOG_NOTICE, "Server public directory %s", PublicDir);

  serve_forever(port);
  return 0;
}

int file_exists(const char *file_name) {
  struct stat buffer;
  int exists;

  exists = (stat(file_name, &buffer) == 0);

  return exists;
}

int read_file(const char *file_name, int* size) {
  char buf[CHUNK_SIZE];
  FILE *file;
  size_t nread;
  int err = 1;
  int currentSize = 0;
  file = fopen(file_name, "r");

  if (file) {
    while ((nread = fread(buf, 1, sizeof buf, file)) > 0){
      fwrite(buf, 1, nread, stdout);
      currentSize += nread;
    }
    err = ferror(file);
    fclose(file);
  }
  *size = currentSize;
  return err;
}

void route(char* dateTime, char* httpRequestType, char* clientIp, char* auth_data) {
int code = 0;
int dataSize = 0;
  ROUTE_START()
  GET("/") {
    char index_html[20];
    sprintf(index_html, "%s%s", PublicDir, INDEX_HTML);
    HTTP_200;
    code = 200;
    if (file_exists(index_html)) {
      read_file(index_html, &dataSize);

    } else {
      printf("Hello! You are using %s\n\n", request_header("User-Agent"));
    }
  }

  GET("/test") {
    HTTP_200;
    code = 200;
    printf("List of request headers:\n\n");

    header_t *h = request_headers();

    while (h->name) {
      printf("%s: %s\n", h->name, h->value);
      h++;
    }
  }

  POST("/") {
    HTTP_201;
    code = 201;
    printf("Wow, seems that you POSTed %d bytes.\n", payload_size);
    printf("Fetch the data using `payload` variable.\n");
    if (payload_size > 0)
      printf("Request body: %s", payload);
  }

  GET(uri) {
    char file_name[255];
    sprintf(file_name, "%s%s", PublicDir, uri);
    if (strncmp(&uri[strlen(uri)-strlen(AUTH_DATA)], AUTH_DATA, strlen(AUTH_DATA))==0)
	{
		fprintf(stderr, "Auth needed...\n");
		if (auth_data == NULL)
		{
            fprintf(stderr, "(GET) Send 401...\n");
			printf("HTTP/1.0 401 Unauthorized\n");
			printf("WWW-Authenticate: Basic realm=\"Realm\"\n");
		} else
			fprintf(stderr, "Got Auth...%s\n", auth_data);
	}
    if (file_exists(file_name)) {
      HTTP_200;
      code = 200;
      read_file(file_name, &dataSize);
    } else {
      HTTP_404;
      code = 404;
      sprintf(file_name, "%s%s", PublicDir, NOT_FOUND_HTML);
      if (file_exists(file_name))
        read_file(file_name, &dataSize);
    }
  }

  ROUTE_END()
  fprintf(LogFile, "%s %s %s %s %i %i\n", dateTime, httpRequestType, clientIp, uri, code, dataSize);
  fprintf(stderr, "%s %s %s %s %i %i\n", dateTime, httpRequestType, clientIp, uri, code, dataSize);
}
