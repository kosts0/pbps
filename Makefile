all: PICOFoxweb

clean:
	@rm -rf *.o
	@rm -rf PICOFoxweb

PICOFoxweb: main.o httpd.o
	gcc -o PICOFoxweb $^

main.o: main.c httpd.h
	gcc -c -o main.o main.c

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c

install: PICOFoxweb
	useradd -c "PICOFoxweb user" -r -s /sbin/nologin -d /var/www/picofoxweb picofoxweb
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
	systemctl daemon-reload
	userdel -f picofoxweb