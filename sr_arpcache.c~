#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/* --------------------------------------------------------------------- */
/* Funkcija koja vraca strukturu o detaljima routiranja.
    Nexthop IP adresu, Interface na koji se proslijediti paket te da li je pronasla interface */
struct detalji_routiranja prikaz_detalja_routiranja(struct sr_instance*, uint32_t);
/* --------------------------------------------------------------------- */

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.

  Ovu funkciju pozivamo svake sekunde te ona prolazi kroz ARP red cekanja i provjerava status
  svih zahtjeva u redu cekanja.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
  struct sr_arpcache *cache = &(sr->cache);
  struct sr_arpreq *req = cache->requests;

  /* Idemo kroz sve zahtjeve u ARP redu cekanja */
  while(req != 0){
    /* Pozivamo funkciju koja obradjuje ARP zathjeve u ARP redu cekanja */
    handle_arpreq(sr, req);
    /* Prelazimo na sljedeci zahtjev */
    req = req->next;
  }

}


/* Pisemo funkciju handle_arpreq kako je definirano u fajlu sr_arpcache.h
   koja ce nam omoguciti obradu ARP paketa u ARP redu cekanja. Ona prolazi kroz ARP red cekanja te
   provjerava da li je prosla sekunda od posljednjeg slanja te da li je poslano manje od 5
   (u ovom slucaju saljemo ARP zahtjeve) ili vise od 5 kada saljemo ICMP poruku te unistavamo zahtjev.
 */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req){
  /* Varijabla koja pohranjuje trenutno vrijeme */
  time_t trenutnovrijeme = time(NULL);

  /* Provjera da li je prosla sekunda od posljednjeg slanja */
  if((trenutnovrijeme - req->sent) > 1.0){
    
    /* Provjera da li je poslano manje od 5 puta */
    if(req->times_sent >= 5){
      
      struct sr_packet *pkt = req->packets;
      while(pkt != 0){
        uint8_t* ip_pkt = (uint8_t*)(pkt->buf + sizeof(sr_ethernet_hdr_t));
        struct sr_ip_hdr* ip_header = (struct sr_ip_hdr*)(pkt->buf + sizeof(sr_ethernet_hdr_t));

          ip_header->ip_ttl++;
          ip_header->ip_sum = 0;
          ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

          /* Saljemo ICMP Network Unreachable */
          salji_icmp_odgovor(sr, pkt->buf, 1, pkt->iface, icmp_type_dest_unreachable, icmp_code_d_net_un);
        
        pkt = pkt->next;
      }

      /* Unistavamo taj ARP zahtjev */
      sr_arpreq_destroy(&(sr->cache), req);
      return;

    } else { 
      /* Saljemo ARP zahtjev */
      posalji_arp_zahtjev(sr, req->ip);

      /* Upisujemo vrijeme kad je posljednji put poslano */
      req->sent = trenutnovrijeme;

      /* Povecavamo broj slanja */
      req->times_sent++;
      return;

    }
  }
  return;
} /* kraj funkcije handle_arpreq() */


/* Pisemo funkciju koja ce slati ARP zahtjev */
void posalji_arp_zahtjev(struct sr_instance* sr, uint32_t ip){
  uint8_t *new_packet; 
  new_packet = calloc(1, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  
  /* Saznajemo sa kojeg cemo interfejsa slati ARP zahtjev */
  struct detalji_routiranja det_rout = prikaz_detalja_routiranja(sr, ip);

  /* Saznajemo IP adresu tog interfejsa routera */
  uint32_t ip_adresa_interf_slanje = vrati_ip_adresu_source_interfejsa_routera(sr, det_rout.interface_poslati);

  /* Saznajemo MAC adresu tog interfejsa routera */
  uint8_t mac_adresa_interf_slanje[ETHER_ADDR_LEN];
  memcpy(mac_adresa_interf_slanje, vrati_mac_adresu_interfejsa_routera(sr, det_rout.interface_poslati), 6 * sizeof(uint8_t));

  /* Definiramo Ethernet i ARP zaglavlje */
  struct sr_ethernet_hdr *ether_hdr = 0;
  struct sr_arp_hdr *arp_hdr = 0;
  ether_hdr = (struct sr_ethernet_hdr*)new_packet;
  arp_hdr = (sr_arp_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));

  /* Punimo Ethernet zaglavlje */
  memcpy(ether_hdr->ether_shost, mac_adresa_interf_slanje, 6 * sizeof(uint8_t)); /* Source MAC */
  ether_hdr->ether_type = ntohs(ethertype_arp); /* Ethernet Type */

  /* Izmjena ARP zaglavlja */
  arp_hdr->ar_op = htons(arp_op_request); /* Postavljamo ovom paketu da je ARP zahtjev */
  arp_hdr->ar_tip = ip; /* Destinacijska IP  */
  arp_hdr->ar_sip = ip_adresa_interf_slanje; /* Izvorisna IP */
  memcpy(arp_hdr->ar_sha, mac_adresa_interf_slanje, 6 * sizeof(uint8_t));

  /* Postavljamo MAC destinacijske adrese ETH i ARP zaglavlja kao Broadcast */
  int i;
  for (i = 0; i < 6; i++) {
		ether_hdr->ether_dhost[i] = 0xff;
		arp_hdr->ar_tha[i] = 0xff;
  }

  arp_hdr->ar_hln = 6; /* Duzina MAC adrese */
  arp_hdr->ar_pln = 4; /* Duzina IP adrese */
  arp_hdr->ar_hrd = htons(1); /* Format MAC adrese */
  arp_hdr->ar_pro = htons(0x0800); /* Format IP adrese */

  /* Saljemo ARP zahtjev */
  sr_send_packet(sr, new_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), det_rout.interface_poslati);

  /* Praznimo zauzetu memoriju */
  free(new_packet);
  
} /* end posalji_arp_zahtjev */

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        /* Izmjenio irfank */
        /* print_addr_ip_int(ntohl(cur->ip)); */
        fprintf(stderr, "%.1x:%.1x:%.1x:%.1x:%.1x:%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

