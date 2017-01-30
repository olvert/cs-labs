/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -Wall -g -o mylogin login.linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

#define AGE_LIMIT 3
#define FAIL_LIMIT 3

#define MAX_USERS 5

#define BAN_OFFSET  60

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}

int getTimeStamp() {
    return (int)time(NULL);
}

void initTimestamps(int timestamps[]) {
    for (int i = 0; i < MAX_USERS; i++) { timestamps[i] = -1; }
}

int main(int argc, char *argv[]) {

	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	char *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

    int timestamps[MAX_USERS];

	sighandler();

    initTimestamps(timestamps);

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
				important);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */

        /* Replace newline character with NULL */
        user[strcspn(user, "\n")] = 0;

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */

            if (passwddata->pwfailed >= FAIL_LIMIT) {

                int current_ts = getTimeStamp();
                int user_ts = timestamps[passwddata->uid];

                /* If user just reached fail limit or retried to soon, init new ban time */
                if (user_ts == -1 || user_ts > current_ts) {
                    user_ts = current_ts + BAN_OFFSET;
                    timestamps[passwddata->uid] = user_ts;

                    printf("You have had to many failed login attempts recently, please try again later.\n");
                    continue;
                }

                /* If ban has expired, reset values */
                timestamps[passwddata->uid] = -1;
                passwddata->pwfailed = 0;
                mysetpwent(passwddata->pwname, passwddata);

            }

            /* Encrypt password */
            c_pass = crypt(user_pass, passwddata->passwd_salt);


			if (!strcmp(c_pass, passwddata->passwd)) {

				printf(" You're in !\n");
                printf(" Number of attempts: %d\n", passwddata->pwfailed);

                /* Reset attempt counter, increment age and update db */
                passwddata->pwfailed = 0;
                passwddata->pwage = passwddata->pwage + 1;
                mysetpwent(passwddata->pwname, passwddata);

                /* Check if password has reached age limit */
                if (passwddata->pwage > AGE_LIMIT)
                    printf(" Password has reached age limit! Please update password.\n");

				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */

			} else {

                /* If login fails, increment attempt counter and update db */
                passwddata->pwfailed = passwddata->pwfailed + 1;
                mysetpwent(passwddata->pwname, passwddata);
            }
		}
		printf("Login Incorrect \n");
	}
	return 0;
}

