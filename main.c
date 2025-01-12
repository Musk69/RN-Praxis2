#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

const int LINES = 40;
const int BUF_MAXLEN = 8193;
const int QUEUE = 10;
const int MAX_CONTENT = 100;
int is_package = 0; // 0 bedeutet package ist kein payload, alles andere ist content length of prev packages payload
int saved_where = -1;

struct file {
    int used; // 0 falls leer, 1 falls inhalt
    char *pfad;
    char *inhalt;
    int con_len;
};

struct file speicher[100];

void init_speicher(){
    for(int i = 0; i < MAX_CONTENT; i++){
        speicher[i].used = 0;
    }
    // fill files foo, bar and baz
    /*speicher[0].used = 1;
    speicher[0].pfad = "/static/foo";
    speicher[0].inhalt = "Foo";

    speicher[1].used = 1;
    speicher[1].pfad = "/static/bar";
    speicher[1].inhalt = "Bar";

    speicher[2].used = 1;
    speicher[2].pfad = "/static/foo";
    speicher[2].inhalt = "Baz";*/
}

void error(char *msg) {
    perror(msg);
    exit(1);
}

void free_lines(int ctr, char *lines[]){
    for(int i = 0; i < ctr-1; i++){
        free(lines[i]);
    }
}

char *build_resp(int i){
    char *response = malloc(300);
    if(response==NULL) {error("malloc failed");}
    memset(response, 0, 100);

    strncpy(response, "HTTP/1.1 200\r\nContent-Length: ", strlen("HTTP/1.1 200\r\nContent-Length: "));
    char num[5];
    memset(num, 0, 5);
    sprintf(num, "%d", speicher[i].con_len);
    strcat(response, num);
    strcat(response, "\r\n\r\n");
    strcat(response, speicher[i].inhalt);
    strcat(response, "\r\n\r\n");

    return (response);
}

int find(char *request) {
    for(int i = 0; i < MAX_CONTENT; i++) {
        // falls file inhalt hat, vergleiche pfade
        if (speicher[i].used == 1) {
            // falls pfad mit request übereinstimmt, gebe i zurück
            if (strncmp(request, speicher[i].pfad, strlen(speicher[i].pfad)) == 0) {
                return i;
            }
        }
    }
    // pfad nicht gefunden
    return -1;
}

int find_empty(){
    for(int i = 0; i < MAX_CONTENT; i++) {
        // falls file inhalt hat, vergleiche pfade
        if (speicher[i].used == 0) {
            return i;
        }
    }
    return -1;
}

void do_payload(char *payload){
    if(saved_where == -1) {
        return;
    }
    // save payload
    speicher[saved_where].inhalt = payload;
}

char *get_req(char *request){
    int len = strlen("/static/foo");
    if(strlen(request) > len) { len = (int)strlen(request); } // zu vergleichende anzahl zeichen auf den längeren beider strings setzen

    //GET /static/foo Anfrage
    if(strncmp(request, "/static/foo", len) == 0) {
        return("HTTP/1.1 200\r\nContent-Length: 3\r\n\r\nFoo\r\n\r\n");
    }
    //GET /static/bar Anfrage
    if(strncmp(request, "/static/bar", len) == 0) {
        return("HTTP/1.1 200\r\nContent-Length: 3\r\n\r\nBar\r\n\r\n");
    }
    //GET /static/baz Anfrage
    if(strncmp(request, "/static/baz", len) == 0) {
        return("HTTP/1.1 200\r\nContent-Length: 3\r\n\r\nBaz\r\n\r\n");
    }

    int c = find(request);
    if(c >= 0) {
        return(build_resp(c));
    }
    //alle anderen GET Anfragen
    return("HTTP/1.1 404\r\nContent-Length: 0\r\n\r\n");
}


char *parse_packet(char *buffer){
    char *crlf = "\r\n";                                //separating argument
    int len_crlf = (int)strlen(crlf);

    char *packet = buffer;

    char *lines[LINES];
    int ctr = 0;

    // heraussuchen aller mit crlf voneinander getrennten strings
    while(1){
        char *res = strstr(packet, crlf);   // erstes vorkommen von crlf in packet finden
        if(res == NULL){ break; }                          // while-schleife beenden, falls kein crlf (mehr)
        char *new_packet = res + len_crlf;                 // neuer zu parsender string (pointer aktualisieren, sodass vorherige line ausgeschlossen ist)

        char *sentence = (char *)malloc(strlen(packet) - strlen(new_packet));
        if(sentence == NULL){error("malloc failed.");}
        strncpy(sentence, packet, (strlen(packet) - strlen(new_packet))); // die zeile
        lines[ctr] = sentence;                             // put sentence in array of lines
        ctr++;
        packet = new_packet;                               // update packet
    }

    // überprüfe ob Anfrage vollständig ist
    if(ctr < 1) { free_lines(ctr, lines); return(NULL); } // falls kein crlf existiert
    if(strncmp(lines[0], crlf, len_crlf) == 0) { free_lines(ctr, lines); return(NULL); } //falls in der 1. Zeile kein inhalt oder nur crlf ist

    // content length default is 0
    int content_length = 0;
    // falls mehr als ein header existiert scanne for content length header and update content length
    if(ctr > 1){
        for(int i = 1; i < ctr; i++){ // zeilen kontrollieren
            if(strncmp(lines[i], "Content-Length:", 15) == 0){
                char str[16];
                sscanf(lines[i], "%[^ ] %d", str, &content_length);
            }
        }
    }
    is_package = content_length;

    char head[strlen(lines[0])];
    memset(head, 0, strlen(lines[0]));
    strncpy(head, lines[0], strlen(lines[0])-len_crlf); // das crlf am ende der line ist unerwünscht und wird rausgeschnitten
    free_lines(ctr, lines);

    regex_t header;
    regmatch_t pmatch[4]; // We have 3 capturing groups + the whole match group
    size_t nmatch = 4; // Same as above

    char reg_header[] = "^([A-Z]+) (.*/.*) (HTTP/[0-9][.][0-9])"; // pattern for first header

    int sol = regcomp(&header, reg_header, REG_EXTENDED); //compile regular expression
    if(sol != 0){ error("error in regcomp"); }

    int match = regexec(&header, head, nmatch, pmatch, 0); //compare buffer to regular expression
    nmatch = header.re_nsub;
    regfree(&header);

    // correct request
    if(match == 0) {
        //parse method
        char method[pmatch[1].rm_eo];
        memset(method, 0, pmatch[1].rm_eo +1);
        strncpy(method, head, pmatch[1].rm_eo);

        // if method = GET
        if((strncmp(method, "GET", 3)) == 0) {
            //parse URI
            int l = pmatch[2].rm_eo - (pmatch[1].rm_eo +1); //len URI ist offset des 2. segments - offset des 1. segments - leerzeichen
            char req[l];
            memset(req, 0, l+1);
            strncpy(req, head+pmatch[2].rm_so, l);

            char *mesg = get_req(req);
            return(mesg);
        }
        // if method = PUT
        else if((strncmp(method, "PUT", 3)) == 0) {
            //parse URI
            int l = pmatch[2].rm_eo - (pmatch[1].rm_eo +1); //len URI ist offset des 2. segments - offset des 1. segments - leerzeichen
            char req[l];
            memset(req, 0, l+1);
            strncpy(req, head+pmatch[2].rm_so, l);

            if(strncmp(req, "/dynamic/", strlen("/dynamic/")) != 0){
                return("HTTP/1.1 403\r\nContent-Length: 0\r\n\r\n");
            }

            int c = find(req);
            if(c >= 0){
                speicher[c].con_len = content_length;
                speicher[c].pfad = req;
                saved_where = c;
                return ("HTTP/1.1 204\r\nContent-Length: 0\r\n\r\n");
            }
            int nc = find_empty();
            if(nc < 0) { error("speicher voll"); }
            speicher[nc].con_len = content_length;
            speicher[nc].pfad = req;
            speicher[nc].used = 1;
            saved_where = nc;
            return("HTTP/1.1 201\r\nContent-Length: 0\r\n\r\n");
        }
        // if method = DELETE
        else if((strncmp(method, "DELETE", 6)) == 0){
            //parse URI
            int l = pmatch[2].rm_eo - (pmatch[1].rm_eo +1); //len URI ist offset des 2. segments - offset des 1. segments - leerzeichen
            char req[l];
            memset(req, 0, l+1);
            strncpy(req, head+pmatch[2].rm_so, l);

            int c = find(req);
            if(c >= 0) {
                speicher[c].inhalt = 0;
                return ("HTTP/1.1 204\r\nContent-Length: 0\r\n\r\n");
            }
            return ("HTTP/1.1 404\r\nContent-Length: 0\r\n\r\n");
        }
        // other method
        else {
            return("HTTP/1.1 501\r\nContent-Length: 0\r\n\r\n");
        }
    }

    // incorrect request
    else {
        return("HTTP/1.1 400\r\nContent-Length: 0\r\n\r\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: webserver <IP> <Port>\n");
        return 1;
    }

    const char *ip = argv[1];
    const char *port = argv[2];

    printf("start");

    // neuen socket erstellen
    int listen_sock;                                    // unser usb-port/unsere Tür die horcht
    struct addrinfo hints;                              // set IP-type, socket-type, unsere IP-adresse
    struct addrinfo *listen_sock_info;                  // hier werden infos über listen_sock gespeichert

    memset(&hints, 0, sizeof hints );          // clear hints sodass kein unsinn drin gespeichert ist
    hints.ai_family = AF_UNSPEC;                        // IPv4 oder IPv6 egal
    hints.ai_socktype = SOCK_STREAM;                    // TCP socket
    hints.ai_flags = AI_PASSIVE;                        // ?

    // automatisches ausfüllen der infos für user listening socket
    listen_sock = getaddrinfo(ip, port, &hints, &listen_sock_info);
    if(listen_sock != 0) {                              // error-checking for getaddrinfo
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(listen_sock));
        exit(1);
    }

    listen_sock = socket(listen_sock_info->ai_family, listen_sock_info->ai_socktype, listen_sock_info->ai_protocol);
    if(listen_sock == -1) { error("server: socket"); } // error-checking

    int set_option = 1; // against bind: address already in use error
    int n = setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&set_option, sizeof(set_option));
    if(n != 0) { error("server: setsockopt"); }         //error checking

    // bind our IP address to listen_sock
    int bin = bind(listen_sock, listen_sock_info->ai_addr, listen_sock_info->ai_addrlen);
    if(bin == -1){error("sever: bind");}                // error-checking

    freeaddrinfo(listen_sock_info);

    // listen for someone that wants to connect
    int lis = listen(listen_sock, QUEUE);
    if(lis == -1){error("server: listen");}

    // variables needed for accept()
    struct sockaddr_in client_addr;
    socklen_t cli_addr_len;
    cli_addr_len = sizeof client_addr;

    // the socket used to connect to someone else and buffer for recv()
    int connect_sock;
    char buffer[BUF_MAXLEN];

    init_speicher(); // initialize speicher

    // while listening (unending loop)
    while(1) {
        //accept connection request
        connect_sock = accept(listen_sock, (struct sockaddr *) &client_addr, &cli_addr_len);
        if (connect_sock == -1) {error("server: accept");}
        memset(buffer, 0, BUF_MAXLEN);

        // when connection is established
        char *ptr = buffer;
        long rec;
        // as long as something is received (the connection is not closed and no error occurs)
        while((rec = recv(connect_sock, ptr, BUF_MAXLEN, 0)) > 0) {
            char *mes = NULL;
            mes = strstr(buffer, "\r\n\r\n"); // search for double crlf in received message
            ptr += rec; // update the ptr in the buffer so that next received messages don't overwrite already receives messages
            if(mes == NULL) {   // if no double crlf is found, begin loop at start (wait for further content)
                continue;
            }

            // save complete package in packet
            long m_len = (mes+2) - buffer;
            char packet[m_len+1];
            memset(packet, 0, m_len+1);
            strncpy(packet, buffer, m_len);

            // if packet is payload of previous package
            if(is_package > 0) {
                do_payload(packet);
                // reset variables for next use
                saved_where = -1;
                is_package = 0;
            }
            // parse received packet and return appropriate message to sent back to client
            else{
                char *msg = parse_packet(packet); // parse the packet and return entsprechenden string

                // unvollständige Anfrage (nicht: Folge von nicht-leeren CRLF-separierten Zeilen)
                if(msg == NULL) {
                    close(connect_sock);
                    continue;
                }
                unsigned len = strlen(msg);
                if (send(connect_sock, msg, len, 0) == -1) {
                    error("server: send");
                }
            }

            // if received message was only one in buffer continue loop in next instance
            if(strlen(mes+4) == 0){
                memset(buffer, 0, BUF_MAXLEN); // clear buffer for next message
                ptr = buffer;
                continue;
            }

            // if not, save content after double crlf
            char rest[strlen(mes+4)];
            strncpy(rest, mes+4, strlen(mes+4));

            memset(buffer, 0, BUF_MAXLEN); // clear buffer for next message
            strncpy(buffer, rest, strlen(rest)); // save start of next packet at start of buffer
            ptr = buffer;
            ptr += (strlen(buffer)); // and update the ptr, so that start of next packet doesn't get overwritten
        }

        if (rec == -1) {                        //error checking
            error("server: recv");
        }

        // if client closes connection
        if (rec == 0) {
            close(connect_sock);                    // close socket
            continue;
        }
    }
}