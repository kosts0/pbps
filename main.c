#include "httpd.h"
#include <sys/stat.h>
#include <syslog.h>
#include<stdio.h>
#include <openssl/ssl.h>
#include <regex.h>
#include <sqlite3.h>
#define CHUNK_SIZE 1024 // read 1024 bytes at a time

// Public directory settings
sqlite3 *db;
char * PublicDir;
char * LogDirectory;
FILE* LogFile;
#define INDEX_HTML "/index.html"
#define NOT_FOUND_HTML "/404.html"
#define AUTH_DATA "auth.html"

struct xyz_t
{
   int Id;
   char* Email;
};

static SSL_CTX *get_server_context(const char *, const char *, const char *);
char* GetClientCertCN(char str[256]){
    char sep[3] = "CN=";
    char * istr;
    istr = strtok (str,sep);
    char* result;
   // Выделение последующих частей
   while (istr != NULL)
   {
      result = istr;
      // Выделение очередной части строки
      istr = strtok (NULL,sep);
   }
   return result;
}
char * UserAccesed;

char* concat(char *s1, char *s2) {

        size_t len1 = strlen(s1);
        size_t len2 = strlen(s2);                      

        char *result = malloc(len1 + len2 + 1);

        if (!result) {
            fprintf(stderr, "malloc() failed: insufficient memory!\n");
            return NULL;
        }

        memcpy(result, s1, len1);
        memcpy(result + len1, s2, len2 + 1);    

        return result;
    }
int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    NotUsed = 0;
    if(argc == 0){
      UserAccesed = NULL;
    }
    else{
      UserAccesed = argv[0];
    }
    printf("Найдено совпадение в СУБД для пользователя: %s\n", UserAccesed);
    return 0;
}
int FindUserByEmail(char* Email){
  char* zErrMsg;
  Email = concat("\"", concat(Email, "\""));
  int result = sqlite3_exec(db, concat("Select Users.Email from Users where Email = ", Email) , callback, 0, &zErrMsg);
  if( result!=SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  }
  return UserAccesed != NULL;
}

// Формирования SSL-контекста для сервера
static SSL_CTX *get_server_context(const char *ca_pem, const char *cert_pem, const char *key_pem) {
  //mydata_index = SSL_get_ex_new_index(0, "mydata index", NULL, NULL, NULL);
	SSL_CTX *ctx;
	/* Формирование контекста с параметрами по-умолчанию */
	if (!(ctx = SSL_CTX_new(SSLv23_server_method()))) {
		fprintf(stderr, "Ошибка SSL_CTX_new\n");
    fprintf(LogFile, "Ошибка SSL_CTX_new\n");
		return NULL;
	}
	/* Установка пути к сертифкату CA */
	if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1) {
		fprintf(stderr, "Не могу определить путь к файлу сертификата CA\n");
    fprintf(LogFile, "Не могу определить путь к файлу сертификата CA\n");
		SSL_CTX_free(ctx);
		return NULL;
	}
  /* Загрузка CA-файла, который будет использоваться для проверки сертификатов клиента */
  SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca_pem));
	/* Установка серверного сертификата, подписанного CA */
	if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr, "Не могу назначить сертификат сервера\n");
    fprintf(LogFile, "Не могу назначить сертификат сервера\n");
		SSL_CTX_free(ctx);
		return NULL;
	}
	/* Установка приватного ключа сервера */
	if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr, "Не могу назначить приватный ключ сервера\n");
    fprintf(LogFile, "Не могу назначить приватный ключ сервера\n");
		SSL_CTX_free(ctx);
		return NULL;
	}
	/* Проверка соответсвия приватного ключа и сертификата сервера */
	if (SSL_CTX_check_private_key(ctx) != 1) {
		fprintf(stderr, "Сертифкат сервера и его приватный ключ не соответсвуют друг другу\n");
    fprintf(LogFile, "Сертифкат сервера и его приватный ключ не соответсвуют друг другу\n");
		SSL_CTX_free(ctx);
		return NULL;
	}
	/* Режим выполнения операций чтения-записи только после успешного (пере)согласования параметров */
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
  /* Клиентская аутентификация по сертификатам */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	/* Принимаем только сертифкаты подписанные самим удостоверяющим центром */
	SSL_CTX_set_verify_depth(ctx, 1);
	/* Возвращаем контекст */
	return ctx;
}

int main(int c, char **v) {
  char *port = c <= 1 ? "8000" : v[1];
  PublicDir = c <=2 ? "./webroot" : v[2];
  LogDirectory = c <=3 ? "./PicoLog.txt" : v[3];
  char *dbPath = c <=4 ? "UsersDatabase.db" : v[4];
  char *keysPath = c <=5 ? "./keys" : v[5];
  LogFile = fopen(LogDirectory, "a");
  syslog (LOG_NOTICE, "Server public directory %s", PublicDir);
  fprintf(stderr, "Server started at port %s with root directory %s. Log path directory: %s. KeyPath : %s\n", port, PublicDir, LogDirectory, keysPath);
  fprintf(LogFile, "Server started at port %s with root directory %s. Log path directory: %s. KeyPath : %s\n", port, PublicDir, LogDirectory, keysPath);
  char *zErrMsg = 0;
  int rc = sqlite3_open(dbPath, &db);
   if( rc ){
     fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
     fprintf(LogFile, "Can't open database: %s\n", sqlite3_errmsg(db));
     sqlite3_close(db);
     return(1);
  }
  // Инициализация OpenSSL
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	// Инициализация контекста сервера
	SSL_CTX *ctx; // контекст сервера
	SSL *ssl;     // SSL-обработчик подключения
	if (!(ctx = get_server_context(concat(keysPath,"/ca/ca_cert.pem"), concat(keysPath,"/server/server_cert.pem"), concat(keysPath, "/server/private/server_key.pem")))) {
		exit(0);
	}

  serve_forever(port, ctx, ssl);
  sqlite3_close(db);
  return 0;
}

int file_exists(const char *file_name) {
  struct stat buffer;
  int exists;

  exists = (stat(file_name, &buffer) == 0);

  return exists;
}

int read_file(const char *file_name, int* size, SSL *ssl) {
  char buf[CHUNK_SIZE];
  FILE *file;
  size_t nread;
  int err = 1;
  int currentSize = 0;
  size_t* strstrwritten;
  file = fopen(file_name, "r");
  int ret = 0;
  if (file) {
    ret = SSL_write(ssl, "HTTP/1.1 200 OK\n\n", 17);
    while ((nread = fread(buf, 1, sizeof buf, file)) > 0){
      ret = SSL_write(ssl, buf, nread);
      currentSize += nread;
    }
    
    err = ferror(file);
    fclose(file);
  }
  *size = currentSize;
  return err;
}

void route(char* dateTime, char* httpRequestType, char* clientIp, char* auth_data, SSL *ssl) {
int code = 0;
int dataSize = 0;
  ROUTE_START()
  GET("/") {
    char index_html[20];
    sprintf(index_html, "%s%s", PublicDir, INDEX_HTML);
    HTTP_200;
    code = 200;
    if (file_exists(index_html)) {
      read_file(index_html, &dataSize, ssl);

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

    char buf[256];
    X509 *err_cert = SSL_get_peer_certificate(ssl);
    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
    char* clientCertificateUser = GetClientCertCN(buf);
    
    if(!FindUserByEmail(clientCertificateUser) && strstr(uri, "private") != NULL)
    {
      HTTP_401;
      code = 401;
      SSL_write(ssl, "HTTP/1.0 401 Unauthorized\n\n", 27);
      printf("Доступ для пользователя %s запрещен\n", clientCertificateUser);
      fprintf(LogFile, "Доступ для пользователя %s запрещен\n", clientCertificateUser);
      SSL_write(ssl, concat("No acess for user ", concat(clientCertificateUser, "\n")), 27 + sizeof(clientCertificateUser));
    }else{
      printf("Доступ для пользователя %s разрешен\n", clientCertificateUser);
      fprintf(LogFile, "Доступ для пользователя %s разрешен\n", clientCertificateUser);
      if (file_exists(file_name)) {
          HTTP_200;
          code = 200;
          read_file(file_name, &dataSize, ssl);
        } else {
          HTTP_404;
          code = 404;
          SSL_write(ssl, "HTTP/1.0 404 Not found\n\n", 24);
          SSL_write(ssl, NOT_FOUND_HTML, 9);
        }
    }
  }

  ROUTE_END()
  fprintf(LogFile, "%s %s %s %s %i %i\n", dateTime, httpRequestType, clientIp, uri, code, dataSize);
  fprintf(LogFile, "==============\n\n");
  fprintf(stderr, "%s %s %s %s %i %i\n", dateTime, httpRequestType, clientIp, uri, code, dataSize);
}