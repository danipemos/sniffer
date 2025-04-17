#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>

typedef struct {
    struct pcap_pkthdr header;
    const u_char *data;
} Packet;


typedef struct Node {
    Packet packet;
    struct Node *next;
} Node;

typedef struct {
    Node *front;
    Node *rear;
} Queue;


Queue queue;


void init_queue() {
    queue.front = NULL;
    queue.rear = NULL;
}


int empty() {
    return queue.front == NULL;
}


void enqueue(Packet packet) {
    Node *newNode = (Node *)malloc(sizeof(Node));
    newNode->packet = packet;
    newNode->next = NULL;

    if (empty()) {
        queue.front = newNode;
    } else {
        queue.rear->next = newNode;
    }
    queue.rear = newNode;
}


//Packet 
int dequeue() {
    if (empty()) {
        Packet emptyPacket = {0}; 
        return 0;
    }

    Node *temp = queue.front;
    Packet packet = temp->packet;
    queue.front = queue.front->next;
    int size= temp->packet.header.len;
    if (queue.front == NULL) {
        queue.rear = NULL;
    }

    free(temp);
    return size;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *data) {
    Packet packet;
    packet.header = *header;
    packet.data = data;
    enqueue(packet);
}

void start_capture() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    time_t start_time, current_time;

    init_queue();

    handle = pcap_open_live("lo", 65536, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device lo: %s\n", errbuf);
        return;
    }
    
    print(pcap_get_buffer_size(handle));
    time(&start_time);
    while (1) {
        time(&current_time);
        if (difftime(current_time, start_time) >= 20.0) {
            break;
        }
        pcap_dispatch(handle, 1, packet_handler, NULL);
    }

    pcap_close(handle);

}