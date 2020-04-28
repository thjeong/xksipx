#include <stdio.h>
#include <string.h>

struct user_entry {
	char userid[48];
	char passwd[48];
};

int main()
{
	struct user_entry user[4096];
	int bytes;
	FILE *fp;

	fp = fopen("USER.DB", "w+");
	strcpy(user[0].userid, "07070156894");
	strcpy(user[0].passwd, "112880");
	strcpy(user[1].userid, "07070154382");
	strcpy(user[1].passwd, "63776377");
	bytes = fwrite(user, sizeof(struct user_entry), 4096, fp);
}
