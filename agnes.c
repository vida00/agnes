#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DL 100 // DEFAULT LENGHT

// gcc main.c -o main -lcrypt

void port_scan(void);
void hash_crack(void);
void dns_resolver(void);
void discover_subDomains(void);

int main(void){
	puts("  .---------.");
	puts("  |.-------.|");
	puts("  ||>run#  ||");
	puts("  ||       ||");
	puts("  |\"-------'|");
	puts(".-^---------^-.");
	puts("| ---~  agnes |");
	puts("\"-------------'");
	puts("\nSelect Option:\n");
	puts("[1] DNS RESOLVER");
	puts("[2] PORT SCAN");
	puts("[3] DISCOVER SUBDIRS");
	puts("[4] HASH CRACK");
	puts("[9] EXIT");

	unsigned int option;

	do{
		printf("\nagnes ~$ ");
		scanf("%i", &option);
		switch(option){
			case 1:
				dns_resolver();
			break;
			case 2:
				port_scan();
			break;
			case 3:
				discover_subDomains();
			break;
			case 4:
				hash_crack();
			break;
			case 9:
				exit(0);
			break;
			default:
				exit(22);
		}
	}while(option != 9);
}

bool check_badchars(char *url){
	bool err = false;
    char *badchars[] = {"http://", "https://", "www."};
    for(int i=0;i<3;i++){
        if(strstr(url, badchars[i])){
            printf("\n[!] Remove: %s", badchars[i]);
            err = true;
        }
    }
	return err;
}

void scan(char *alvo, int port){

	int conn, sock;

	struct sockaddr_in targ;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == -1)
        puts("\n[!] Could not create socket\n");
    targ.sin_family = AF_INET;
    targ.sin_port = htons(port);
    targ.sin_addr.s_addr = inet_addr(alvo);
    conn = connect(sock, (struct sockaddr *)&targ, sizeof targ);
    if(conn == 0){
        printf("[+] Open: %d\n", port);
        close(sock);
        close(conn);
    } else {
        close(sock);
        close(conn);
  }
}
void dns_resolver(void){

	char url[DL];

	printf("\n[ DNS RESOLVER ]\nURL ~$ ");
	scanf("%s", url);

    if(check_badchars(url)){
        printf("\nURL ~$ ");
        scanf("%s", url);
    }

	struct hostent *target = gethostbyname(url);

	if(target == NULL)
		puts("\n[!] Not Found");
	else
		printf("\n[+] IP: %s\n", inet_ntoa(*((struct in_addr *)target->h_addr)));
}

void discover_subDomains(void){

	FILE *fp;

	char url[DL], wordlist_path[DL], subdomain[DL], full_path[DL];
	bool found = false;

	printf("\n[ DISCOVER DIRS ]\nURL ~$ ");
	scanf("%s", url);

    if(check_badchars(url)){
        printf("\nURL ~$ ");
        scanf("%s", url);
    }

	printf("Wordlist Path ~$ ");
	scanf("%s", wordlist_path);

	fp = fopen(wordlist_path, "r");

	if(fp == NULL){
		puts("\n[!] Could not open file\n\n\n");
		main();
	}
	
	while(fscanf(fp, "%s", subdomain) != EOF){
		strcat(strcpy(full_path, subdomain), ".");
		strcat(full_path, url);

		struct hostent *target = gethostbyname(full_path);

		if(target != NULL)
			printf("\n[+] Find: %s -> %s", full_path, inet_ntoa(*((struct in_addr *)target->h_addr)));
			found = true;
	}
	if(!found)
		puts("\n[!] Not Found");

	fclose(fp);
}

void port_scan(void){

	int sock, conn, i;
	char ip[DL];
	unsigned int select_port;

	// TOP PORTS
	int top[] = {21,22,23,25,80,110,139,443,445,3306,3389,8080};

	printf("\n[ PORT SCAN ]\nTarget IP ~$ ");
	scanf("%s", ip);

	printf("\n[1] TOP PORTS\n[2] ALL PORTS\nagnes~$ ");
	scanf("%i", &select_port);

	printf("\n");
	switch(select_port){
		case 1:
			for(i=0;i<5;i++){
				scan(ip, top[i]);
			}
			puts("[$] Finish");
			exit(0);
		break;
		case 2:
			for(i=0;i<65535;i++){
				scan(ip, top[i]);
			}
			puts("[$] Finish");
			exit(0);
		break;
	}
}

void hash_crack(void){

	char wordlist_path[DL];
	char full_hash[DL + 300];
	char only_salt[DL + 50];
	char *hash_line;

	char line[DL + 300];
	bool succ;
	FILE *fp;

	printf("\n[ HASH CRACK ]\nFull Hash ~$ ");
	scanf("%s", full_hash);

	printf("Only Hash ~$ ");
	scanf("%s", only_salt);

	printf("Wordlist Path ~$ ");
	scanf("%s", wordlist_path);

	printf("\n");

	fp = fopen(wordlist_path, "r");

	if(fp == NULL){
		puts("[!] Could not open file\n\n\n");
		main();
	}

	while(fscanf(fp, "%s", line) != EOF){
		hash_line = (char *) crypt(line, only_salt);
		if(strcmp(full_hash, hash_line) == 0){
			printf("[+] Find: %s\n", line);
			succ = true;
			break;
		} else {
			printf("[?] Try: %s\n", line);
		}
	}
	if(!succ)
		printf("\n[!] Not Found\n");
	fclose(fp);
}
