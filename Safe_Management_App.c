#define _CRT_SECURE_NO_WARNINGS
#define SAFEGUARD_PATH "/home/zc-zhai/Desktop/user"
#define SAFEGUARD "/home/zc-zhai/Documents/SafeGuard/"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#define NETLINK_TEST    30
#define MSG_LEN            125
#define MAX_PLOAD        125
#define LOGIN_MESSAGE "Identity Certification Passed!"
#define LOGOUT_MESSAGE "Service Exit!                 "

typedef struct _user_msg_info
{
    struct nlmsghdr hdr;
    char  msg[MSG_LEN];
} user_msg_info;

typedef struct
{
	char username[20];
	char userpassword[20];
}LOADSYSTEM;

void encrypt(char *pwd)
{
	while ((*pwd) != '\0')
	{
		*pwd = *pwd ^ 15;
		pwd++;
	}
}

void CreatUser()
{
	FILE *fp;
	LOADSYSTEM user;
	int i;
	if ((fp = fopen(SAFEGUARD_PATH, "a+")) == NULL)
	{
		printf("File Open Failed!\n");
		exit(0);
	}
	//fseek(fp, 0L, SEEK_END);
	/*for (i = 0; i < 3; i++)
	{
		printf("Enter user%d name&password:", i + 1);
		scanf("%s%s", user.username, user.userpassword);
		encrypt(user.userpassword);
		fprintf(fp, "%s %s\n", user.username, user.userpassword);
	}*/
	printf("Enter username and password:\n");
	scanf("%s%s", user.username, user.userpassword);
	encrypt(user.userpassword);
	fprintf(fp, "%s %s\n", user.username, user.userpassword);
	if (fclose(fp))
	{
		printf("File Close Failed!\n");
		exit(0);
	}
	printf("Create User Successfully!\n");
}

int CompareUser(LOADSYSTEM user)
{
	char name[40], password[20], name1[40];
	int flag = 0;
	FILE *fp;
	if ((fp = fopen(SAFEGUARD_PATH, "r")) == NULL)
	{
		printf("File Open Failed!\n");
		return 0;
	}
	strcpy(name, user.username);
	strcpy(password, user.userpassword);
	encrypt(password);
	strcat(name, " ");
	strcat(name, password);
	strcat(name, "\n");
	//printf("%s", name);
	while (!feof(fp))
	{
		fgets(name1, 40, fp);
		//printf("%s", name1);
		if (strcmp(name, name1) == 0)
		{
			flag = 1;
			break;
		}
	}
	if (fclose(fp))
	{
		printf("File Close Failed!\n");
		exit(0);
	}
	return flag;
}

int netlink_user(char *umsg)
{
    int skfd;
    int ret;
    user_msg_info u_info;
    socklen_t len;
    struct nlmsghdr *nlh = NULL;
    struct sockaddr_nl saddr, daddr; 

    /* 创建NETLINK socket */
    skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if(skfd == -1)
    {
        perror("create socket error\n");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK; //AF_NETLINK
    saddr.nl_pid = 100;  //端口号(port ID) 
    saddr.nl_groups = 0;
    if(bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)
    {
        perror("bind() error\n");
        close(skfd);
        return -1;
    }

    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0; // to kernel 
    daddr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
    memset(nlh, 0, sizeof(struct nlmsghdr));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = saddr.nl_pid; //self port

    memcpy(NLMSG_DATA(nlh), umsg, strlen(umsg));
    ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr_nl));
    if(!ret)
    {
        perror("sendto error\n");
        close(skfd);
        exit(-1);
    }
    printf("send kernel:%s\n", umsg);

    memset(&u_info, 0, sizeof(u_info));
    len = sizeof(struct sockaddr_nl);
    ret = recvfrom(skfd, &u_info, sizeof(user_msg_info), 0, (struct sockaddr *)&daddr, &len);
    if(!ret)
    {
        perror("recv form kernel error\n");
        close(skfd);
        exit(-1);
    }

    printf("from kernel:%s\n", u_info.msg);
    close(skfd);

    free((void *)nlh);
    return 0;
}

int main()
{
	char c_tmp, op, opt;
	int s_pid = -1;
	char ch_pid[20];
	int status = 1;
	char filename[100];
	char *find;
	char full_filename[200];
	strcpy(full_filename,SAFEGUARD);

	while (1){
		printf("Sign In or Sign Up?\n");
		printf("Enter 1 to sign in or 2 to sign up:");
		op = getchar();
		while((c_tmp = getchar()!='\n') && c_tmp!=EOF);
		if (op == '1'){
			LOADSYSTEM user;
			int result;
			printf("Enter username:");
			scanf("%s", user.username);
			printf("Enter password:");
			scanf("%s", user.userpassword);
			result = CompareUser(user);
			if (result){
				printf("Sign In Successfully!\n");
				netlink_user(LOGIN_MESSAGE);
				printf("Status: Steel Safe Unlocked!\n");
				break;
			}
			else
			{
				printf("Sign In With Failure!\n");
			}
		}
		else{
			if (op == '2')
				CreatUser();
			else
				printf("Invalid option!\n");
		}
	}
	while((c_tmp = getchar()!='\n') && c_tmp!=EOF);
	while (1){
		printf("Plz enter 'l' to get file list, 'o' to open file, 'e' to quit:");
		opt = getchar();
		while((c_tmp = getchar()!='\n') && c_tmp!=EOF);
		if (opt == 'e'){
			printf("Sign Out Successfully!\n");
			netlink_user(LOGOUT_MESSAGE);
			printf("Status: Steel Safe Locked!\n");
			break;
		}
		else if (opt == 'o'){
			if(s_pid = fork()){
				//wait(&status);
				sprintf(ch_pid,"%d",s_pid);
				netlink_user(ch_pid);
				printf("S_pid sent.\n");
				wait(&status);
				printf("P_process finished.\n");
			}
			else{
				printf("Plz enter the filename(relative path):\n");
				fgets(filename,100,stdin);
				find = strchr(filename, '\n');          
				if(find)                           
    					*find = '\0';
				strcat(full_filename,filename);
				execl("/usr/bin/vi","vi",full_filename,(char *)0);
				printf("execl failed.\n");
				exit(2);
			}
		}
		else if (opt == 'l'){
			if(s_pid = fork()){
				//wait(&status);
				sprintf(ch_pid,"%d",s_pid);
				netlink_user(ch_pid);
				printf("S_pid sent.\n");
				wait(&status);
				printf("P_process finished.\n");
			}
			else{
				printf("Plz enter the filename(relative path):\n");
				fgets(filename,100,stdin);
				find = strchr(filename, '\n');          
				if(find)                           
    					*find = '\0';
				strcat(full_filename,filename);
				execl("/bin/ls","ls","-l",full_filename,(char *)0);
				printf("execl failed.\n");
				exit(2);
			}
		}
		else
			printf("Invalid option!\n");
	}
	return 0;
}