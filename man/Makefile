.include<../mkinfo.mk>

realinstall:
	cp ${DAEMON_NAME}.8 /usr/share/man/man8/${DAEMON_NAME}.8
	makewhatis /usr/share/man

clean:
	rm /usr/share/man/man8/${DAEMON_NAME}.8
	makewhatis /usr/share/man

.include <bsd.man.mk>
.include <bsd.subdir.mk>
