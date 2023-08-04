#ifndef __TC_PERH_H
#define __TC_PERH_H

#define MAX_SIZE 1400

struct http_response{
    char http[8];
    char b1;
    char scode[3];
    char b2;
};

struct uri_s{
    char p1[3];
    char b1;
    char p2[3];
};

// Never count the extra spaces -- 
struct uri_l{
    char p1[3];
    char b1;
    char p2[8];
};

struct get_request_s{
    char req[3];
    char b1[2];
    struct uri_s uri;
    char b2;
    char http[8];
    char end;
};

struct get_request_l{
    char req[3];
    char b1[2];
    struct uri_l uri;
    char b2;
    char http[8];
    char end;
};

struct post_request {
    char req[4];
    char b1;
    char uri[16];
    char b2;
    char http[8];
};


/* definition of a sample sent to user-space from BPF program */
struct event {
	char payload[MAX_SIZE];
};


key_t msg1 = 6123;

int msgId;

struct msgIPCbuf{
    long int mtype;
    char payload[MAX_SIZE];
};


#endif /* __TC_PERH_H */
