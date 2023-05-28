all: PICOFoxweb

clean:
	@rm -rf *.o
	@rm -rf PICOFoxweb

PICOFoxweb: main.o httpd.o
	gcc -o PICOFoxweb $^ -lssl -lcrypto -lsqlite3

main.o: main.c httpd.h
	gcc -c -o main.o main.c -lssl -lcrypto -lsqlite3

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c -lssl -lcrypto -lsqlite3

install: PICOFoxweb
	useradd -c "PICOFoxweb user" -r -s /sbin/nologin -d /var/www/picofoxweb picofoxweb
	cp -r keys -t /var/www/
	cp -r UsersDatabase.db -t /var/www/
	install -o root -g root -m 0755 PICOFoxweb /usr/local/sbin/                       
	install -o root -g root -m 0644 picofoxweb.service /etc/systemd/system/           
	systemctl daemon-reload                                                           
	systemctl restart picofoxweb.service
	cp -r webroot -t /var/www/
	chown -R picofoxweb:picofoxweb /var/www

uninstall:
	systemctl stop picofoxweb
	rm -rf /var/www/picofoxweb
	rm -f /usr/local/sbin/PICOFoxweb
	rm -f /etc/systemd/system/picofoxweb.service
	rm -f /user/local/sbin/UserDatabase.db
	rm -rf /var/www/keys
	systemctl daemon-reload
	userdel -f picofoxweb