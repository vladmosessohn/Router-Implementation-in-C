#include "skel.h"
 
struct route_table_entry *rtable;
struct arp_entry *arp_table;
// tabelele
int size_route_table;
int size_arp_table;
// dimensiunea tabelelor 


 


struct route_table_entry {
    uint32_t prefix;
    uint32_t next_hop;
    uint32_t mask;
    int interface;
} __attribute__((packed));
// structa pentru o linie din tabela de rutare
// luata din laborator


struct arp_entry {
    uint32_t ip;
    uint8_t mac[6];
};
// structura pentru o linie din tabela arp
// luata din laborator


long unsigned int size_eth = sizeof(struct ether_header);
long unsigned int size_iph = sizeof(struct iphdr);
long unsigned int size_route_entry = sizeof(struct route_table_entry);
long unsigned int size_arp_entry = sizeof(struct arp_entry);
long unsigned int size_icmp = sizeof(struct icmphdr);
// am defint cate o variabla pentru size-ul fiecarei structuri pentru a imi fi mai usor
// sa scriu codul
 
struct arp_entry *get_arp_entry(__u32 ip) {
	int i, flag = 0;
	struct arp_entry *element = malloc(size_arp_entry);
    for(i = 0; i < size_arp_table; ++i){
		if(arp_table[i].ip == ip) {
			element =  &arp_table[i];
			flag = 1;
		}
	}
	if(flag == 0) {
		return NULL;
	}
    return element;
}
// functie 
 
int parse_rtable(int i){
char s[100], *ptr;
FILE *fp = fopen("rtable.txt", "r");
while(fgets(s, 100, fp)){
	// citim linie cu linie pana nu mai avem ce sa citim
	// despartim linia in cuvinte folosind strtok
	ptr = strtok(s," ");
	rtable[i].prefix = inet_addr(ptr);
	// primul cuvant reprezinta prefixul si folosesc functia deja
	// implementata in schelet inet_addr() pentru a il converti intr-o adresa
	ptr = strtok(NULL, " ");
	rtable[i].next_hop = inet_addr(ptr);
	// al doilea cuvant reprezinta next_hop-ul si folosesc functia deja
	// implementata in schelet inet_addr() pentru a il converti intr-o adresa
	ptr = strtok(NULL, " ");
	rtable[i].mask = inet_addr(ptr);
	// al treilea cuvant reprezinta masca si folosesc functia deja
	// implementata in schelet inet_addr() pentru a il converti intr-o adresa
	ptr = strtok(NULL, " ");
	rtable[i].interface = atoi(ptr);
	// al cuvant cuvant reprezinta interfata si folosesc functia deja
	// implementata in C inet_addr() pentru a il converti in int

	//printf("%d %d %d %d\n",rtable[i].prefix,rtable[i].next_hop,rtable[i].mask,rtable[i].interface);
	++i;
}
return i;
}
 
 
int most_bits(struct route_table_entry elem, __u32 dest_ip, int i){
	if((elem.mask & dest_ip) != elem.prefix) {
		return -1;
	} 
	if((elem.mask & dest_ip) == elem.prefix) {
		while(elem.mask) {
			i = i + (elem.mask & 1);
			elem.mask = (elem.mask >> 1);
		}
	}
	return i;
}

int caut_bin(int stanga, int dreapta, __u32 dest_ip) {
	if(stanga > dreapta) {
		return -1;
	} else {
		int mij = (stanga + dreapta) / 2;
		if(rtable[mij].prefix == (dest_ip & rtable[mij].mask)) {
			return mij;
		}
		if(rtable[mij].prefix > (dest_ip & rtable[mij].mask)) {
			caut_bin(stanga, mij - 1, dest_ip);
		} else {
			caut_bin(mij + 1, dreapta, (dest_ip & rtable[mij].mask));
		}
	}
	return -1;
}
// cautarea binara astfel incat sa gasim un element cu
// prefixul egal cu dest_ip & masca
 
struct route_table_entry *get_best_route(__u32 dest_ip) {
	struct route_table_entry *elem = malloc(size_route_entry);
	int maxim = 0, flag = 0;

	int index = caut_bin(0, size_route_table - 1, dest_ip);
	// cautam binar un element cu prefixul egal cu dest_ip
	while(index > 0) {
		if(rtable[index].prefix != rtable[index - 1].prefix) {
			break;
		}
		index = index - 1;
	}
	// mergem la primul element cu prefixul egal cu dest_ip & masca
	while(index < size_route_table){
		if(most_bits(rtable[index], dest_ip, 0) > maxim){
			flag = 1;
			maxim = most_bits(rtable[index], dest_ip, 0);
			elem = &rtable[index];
		}
		index++;
		if(rtable[index].prefix > dest_ip) {
			break;
		}
	}
	// vedem care element cu prefixul egal cu dest_ip are
	// masca cu cei mai multi biti setati
	// cand se termina intrarile cu prefixul egal cu dest_ip dam break
	// deci practic cautarea este facuta in O(log n + nr_finit de operatii)
	// =>cautarea best_route-ului se realizeaza in O(logn)
	if(flag == 0) {
		return NULL;
	} else {
		return elem;
	}
}


 
int parse_arp(int i){
	FILE *file = fopen("arp_table.txt", "r");
	char s[100], *ptr;
	// similar cu parse_rtable(), citim linie cu linie
	// pana la finalul fisierului
	while(fgets(s, 100, file)){
		// despartim in cuvinte folosind strtok
		ptr = strtok(s," ");
		arp_table[i].ip = inet_addr(ptr);
		// conviertim primul cuvant folosind functia deja implementata
		// in schelet inet_addr() intr-o adresa
		ptr = strtok(NULL," ");	
		hwaddr_aton(ptr, arp_table[i].mac);
		// convertim al doilea cuvant intr-o adresa mac folosind functia
		// functia deja implementata hwaddr_aton()

		//printf("%d %d \n", arp_table[i].ip, arp_table[i].mac);
		++i;
	}
	return i;
}


void swap1(struct route_table_entry *x, struct route_table_entry *y) 
{ 
    struct route_table_entry temp = *x; 
    *x = *y; 
    *y = temp; 
}
// am numit functia de swap swap1 sa nu se confunde cu cea din biblioteca C

void heapyfy(struct route_table_entry *rtable, int size_route_table, int i) {
	int max = i, l = 2 * i + 1, r = l + 1;
	if(l < size_route_table && rtable[l].prefix > rtable[max].prefix) {
		max = l;
	}
	if(r < size_route_table && rtable[r].prefix > rtable[max].prefix) {
		max = r;
	}
	if(max != i) {
		swap1(&rtable[i], &rtable[max]);
		heapyfy(rtable, size_route_table, max);
	}
}
// sortare heapsort

void heapsort(struct route_table_entry *rtable, int size_route_table) {
	for(int i = size_route_table / 2 - 1; i >= 0; i--) {
		heapyfy(rtable, size_route_table, i);
	}

	for(int i = size_route_table - 1; i >= 0; i--) {
		swap1(&rtable[0], &rtable[i]);
		heapyfy(rtable, i, 0);
	}
}

void sort_rtable() {
	heapsort(rtable, size_route_table);
	for(int i = 0; i < size_route_table; ++i) {
		printf("%d %d %d %d\n", rtable[i].prefix, rtable[i].next_hop, rtable[i].mask, rtable[i].interface);
	}
}
// sortare + afisare tabela rutare 


void daddr_update(struct iphdr *iph) {
	struct iphdr *aux;
	aux = iph;
	iph->daddr = iph->saddr;
	iph->saddr = aux->daddr;
	// interschimbam daddr-ul cu saddr pentru a putea trimite pachetul de unde a venit
}

void packet_interface_update(struct iphdr *iph, struct ether_header *eh, packet *m) {
	struct route_table_entry *best_r;
	struct arp_entry *best_arp_entry;
	best_r = get_best_route(iph->daddr);
    best_arp_entry = get_arp_entry(best_r->next_hop);
    memcpy(eh->ether_dhost, best_arp_entry->mac, 6);
   	m->interface = best_r->interface;

   	// gasim cel mai bun next_hop pentru pachet
   	// actualizam in antetul ether_header adresa mac
   	// dupa setam interfata pachetului cu interfata celei
   	// mai bune intrari urmatoare pentru pachet pentru 
   	// a-l putea trimite mai departe
}


void set_icmp_type(struct iphdr *iph, struct icmphdr *imp) {
	if(iph->ttl <= 1) {
		imp->type = ICMP_TIME_EXCEEDED;		
	}
	if(get_best_route(iph->daddr) == NULL) {
		imp->type = ICMP_DEST_UNREACH;
	}
	// setam tipul icmp fie cu icmp timeout, fie cu imcp host_unreacheable
}

int main(int argc, char *argv[]){
	setvbuf(stdout, NULL, _IONBF, 0); 
	rtable = malloc(65000 * size_route_entry);
	arp_table = malloc(15 * size_arp_entry);
	// alocam memorie pentru tabele
	size_route_table = parse_rtable(0);
	sort_rtable();
	size_arp_table = parse_arp(0);
 	// pasram tabelele + sortarea celei de rutare
	packet m;
	int rc;
 
	init();
 	
 	
 	struct iphdr *iph;
 	struct ether_header *eh;
	struct icmphdr *imp;
 

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		/* Students will write code here */
		eh = (struct ether_header*) m.payload;
		if(eh->ether_type == htons(ETHERTYPE_IP)){
			// cazul in care tipul lui ether_header este IP
			iph = (struct iphdr*)(m.payload + size_eth);

			if(iph->daddr == inet_addr(get_interface_ip(m.interface))) {
				
				imp = (struct icmphdr *) (m.payload + size_eth + size_iph);
				imp->type = ICMP_ECHOREPLY;

				imp->checksum = 0;
				imp->checksum = ip_checksum(imp, size_icmp);

				iph->ttl = iph->ttl - 1;

				
				daddr_update(iph);
				
				iph->check = 0;
    			iph->check = ip_checksum(iph, size_iph);

				memcpy(eh->ether_dhost, eh->ether_shost, 6);
				get_interface_mac(m.interface, eh->ether_shost);
			} else {

				if(iph->ttl <= 1 || get_best_route(iph->daddr) == NULL){
					imp = (struct icmphdr *) (m.payload + size_eth + size_iph);
					
					set_icmp_type(iph, imp);

					imp->checksum = 0;
					imp->checksum = ip_checksum(imp, size_icmp);
					// actualizam checksum-ul din icmp

					iph->ttl = 7;
					// setam ttl-ul cu un numar oarecare

					
					daddr_update(iph);
					// vrem sa notificam gazda ca pachetul nu a fost trimis cu succes
					// de aceea setam adresa pachetului cu adresa gazdei
					iph->protocol = 1;
					iph->tot_len = htons(size_iph + size_icmp);
					// updatam marimea header-ului de ip

					iph->check = 0;
    				iph->check = ip_checksum(iph, size_iph);
    				// actualizam checksum-ul

					memcpy(eh->ether_dhost, eh->ether_shost, 6);
					get_interface_mac(m.interface, eh->ether_shost);
					m.len = size_eth + size_icmp + size_iph;
					// setam lungimea pachetului
					send_packet(m.interface, &m);
					continue;
				}

	        	uint16_t prev_sum = iph->check;
    	    	iph->check = 0;
    			iph->check = ip_checksum(iph, size_iph);
 
	        	if(prev_sum == iph->check){
    	    		// checksum ok
        		} else {
        			continue;
        		}
        		// verificam checksum-ul sa fie egal cu cat era inainte sa-l
        		// actualizam
        		// daca nu este egal, "aruncam" pachetul

        		iph->ttl = iph->ttl - 1;
        		iph->check = 0;
    			iph->check = ip_checksum(iph, size_iph);

        		packet_interface_update(iph, eh, &m);
			}
 
 
		}
		send_packet(m.interface, &m);
	}
 
}
