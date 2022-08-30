#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdlib.h>
#include <termios.h> 

#define PASS_MAX_LEN 100

//gcc main.cpp -o main -lpam -lpam_misc

int readPass(int echo, char password[])
{
	static struct termios oldt, newt;
	int i = 0;
	int c;

	/*saving the old settings of STDIN_FILENO and copy settings for resetting*/
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;

	/*setting the approriate bit in the termios struct*/
	if(echo == 1)
		newt.c_lflag &= ~(ECHO);

	/*setting the new bits*/
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);

	/*reading the password from the console*/
	while ((c = getchar()) != '\n' && c != EOF && i < 100) {
		password[i++] = c;
	}
	password[i] = '\0';

	/*resetting our old STDIN_FILENO*/
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	return strlen(password);
}


// int conversation(int num_msg, const struct pam_message **msg,
// 		 struct pam_response **resp, void *appdata_ptr)
// { /* We malloc an array of num_msg responses */
// 	struct pam_response *array_resp = (struct pam_response *)malloc(
// 		num_msg * sizeof(struct pam_response));
// 	for (int i = 0; i < num_msg; i++) {
// 		/* resp_retcode should be set to zero */
// 		array_resp[i].resp_retcode = 0;

// 		/* The message received from the module */
// 		const char *msg_content = msg[i]->msg;

// 		/* Printing the message (e.g. "login:", "Password:") */
// 		printf("%s", msg_content);

// 		char pass[PASS_MAX_LEN];

// 		/* This is a function that reads a line from console without printing it
// 		 * just like when you digit your password on sudo. I'll publish this soon */
// 		readPass(pass);

// 		/* Malloc-ing the resp string of the i-th response */
// 		array_resp[i].resp = (char *)malloc(strlen(pass) + 1);

// 		/* Writing password in the allocated string */
// 		strcpy(array_resp[i].resp, pass);
// 	}

// 	/* setting the param resp with our array of responses */
// 	*resp = array_resp;

// 	/* Here we return PAM_SUCCESS, which means that the conversation happened correctly.
// 	 * You should always check that, for example, the user didn't insert a NULL password etc */
// 	return PAM_SUCCESS;
// }

int conversation(int num_msg, const struct pam_message **msg,
		 struct pam_response **resp, void *appdata_ptr)
{ /* We malloc an array of num_msg responses */
	struct pam_response *array_resp = (struct pam_response *)malloc(
		num_msg * sizeof(struct pam_response));
	for (int i = 0; i < num_msg; i++) {

		// char *string=NULL;
		// int nc;

		/* resp_retcode should be set to zero */
		array_resp[i].resp_retcode = 0;

		/* The message received from the module */
		const char *msg_content = msg[i]->msg;

		/* Printing the message (e.g. "login:", "Password:") */
		printf("%s", msg_content);

		char pass[PASS_MAX_LEN];

		switch (msg[i]->msg_style)
		{
		case PAM_PROMPT_ECHO_OFF:
			readPass(PAM_PROMPT_ECHO_OFF, pass);
			break;
		case PAM_PROMPT_ECHO_ON:
			readPass(PAM_PROMPT_ECHO_ON, pass);
			break;
		default:
			break;
		}

		/* Malloc-ing the resp string of the i-th response */
		array_resp[i].resp = (char *)malloc(strlen(pass) + 1);

		/* Writing password in the allocated string */
		strcpy(array_resp[i].resp, pass);
	}

	/* setting the param resp with our array of responses */
	*resp = array_resp;

	/* Here we return PAM_SUCCESS, which means that the conversation happened correctly.
	 * You should always check that, for example, the user didn't insert a NULL password etc */
	return PAM_SUCCESS;
}

static struct pam_conv conv = {
	conversation, /* Our conversation function */
	NULL /* We don't need additional data now*/
};


int main()
{
    pam_handle_t *handle = NULL;
    const char* service_name = "keystrokes-auth"; //email-auth keystrokes-auth
    int retval;
    char *username;
    
    retval = pam_start(service_name, NULL, &conv, &handle);

    if(retval != PAM_SUCCESS)
    {
        fprintf(stderr, "Failure in pam authentication: %s\n",
			pam_strerror(handle, retval));
		return 1;
	}

    retval = pam_authenticate(handle, 0);
    if (retval != PAM_SUCCESS) {
		fprintf(stderr, "Failure in pam authentication: %s\n",
			pam_strerror(handle, retval));
		return 1;
	}


    pam_get_item(handle, PAM_USER, (const void **)&username);
    printf("WELCOME, %s\n", username);
    
    pam_end(handle, retval); /* ALWAYS terminate the pam transaction!! */
}