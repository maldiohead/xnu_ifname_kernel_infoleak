
//
//  main.c
//  config_ocleak
//
//  Created by maldiohead on 2019/1/3.
//  Copyright © 2019 maldiohead. All rights reserved.
//

//
//  main.c
//  configd_leak
//
//  Created by maldiohead on 2019/1/3.
//  Copyright © 2019 maldiohead. All rights reserved.
//


#import <Foundation/Foundation.h>
#include <stdio.h>
#include <MacTypes.h>
#include <notify.h>
#include <sys/sysctl.h>
#include <sys/kern_event.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <os/availability.h>
#import  <os/activity.h>
#include <netinet/in.h>


static    dispatch_queue_t         S_kev_queue;
static    dispatch_source_t        S_kev_source;
static    CFMutableDictionaryRef   cached_keys    = NULL;
static    CFMutableDictionaryRef   cached_set    = NULL;
static    CFMutableArrayRef    cached_removals    = NULL;
static    CFMutableArrayRef    cached_notifys    = NULL;

#define TIMER_INTERVAL        (6LL * NSEC_PER_SEC)
#define MAX_TIMER_COUNT        20



void cache_open(void)
{
    cached_keys     = CFDictionaryCreateMutable(NULL,
                                                0,
                                                &kCFTypeDictionaryKeyCallBacks,
                                                &kCFTypeDictionaryValueCallBacks);
    cached_set      = CFDictionaryCreateMutable(NULL,
                                                0,
                                                &kCFTypeDictionaryKeyCallBacks,
                                                &kCFTypeDictionaryValueCallBacks);
    cached_removals = CFArrayCreateMutable(NULL,
                                           0,
                                           &kCFTypeArrayCallBacks);
    cached_notifys  = CFArrayCreateMutable(NULL,
                                           0,
                                           &kCFTypeArrayCallBacks);
    
    return;
}

struct net_event_data {
    u_int32_t    if_family;
    u_int32_t    if_unit;
    char        if_name[16];
};



struct kev_in_collision {
    struct net_event_data link_data; /* link where ARP was received on */
    struct in_addr ia_ipaddr;    /* conflicting IP address */
    u_char hw_len;            /* length of hardware address */
    u_char hw_addr[0];        /* variable length hardware address */
};

static void
copy_if_name(const struct net_event_data * ev, char * ifr_name, int ifr_len)
{
    printf("show leaked data:\n");
    
    for(int i=0;i<16;i++)
    {
        printf("%0.2x ",(uint8_t)ev->if_name[i]);
    }
    printf("\n");
//    snprintf(ifr_name, ifr_len, "%s%d", ev->if_name, ev->if_unit);
    return;
}

static void
processEvent_Apple_Network(struct kern_event_msg *ev_msg)
{
    
    size_t        dataLen    = (ev_msg->total_size - KEV_MSG_HEADER_SIZE);
    void *        event_data    = &ev_msg->event_data[0];
    char        ifr_name[16];
    Boolean        handled    = TRUE;
    switch (ev_msg->kev_subclass) {
            
            
            case KEV_DL_SUBCLASS : {
                struct net_event_data * ev;
                
                ev = (struct net_event_data *)event_data;
                
                switch (ev_msg->event_code) {
                    case KEV_DL_PROTO_ATTACHED :{
                        copy_if_name(ev, ifr_name, sizeof(ifr_name));
                     //   struct kev_dl_proto_data * protoEvent;
                        //protoEvent = (struct kev_dl_proto_data *)event_data;
                       
                    }
                }
            
                break;
            
    }

case KEV_INET_ARPCOLLISION : {
    struct kev_in_collision * ev;
    
    ev = (struct kev_in_collision *)event_data;
    if ((dataLen < sizeof(*ev))
        || (dataLen < (sizeof(*ev) + ev->hw_len))) {
        handled = FALSE;
        break;
    }
    break;
    
}
        default:
          //  printf("other\n");
            break;
    return;
    }
}
static Boolean
eventCallback(int so)
{
    union {
        char            bytes[1024];
        struct kern_event_msg    ev_msg1;    // first kernel event
    } buf;
    struct kern_event_msg    *ev_msg        = &buf.ev_msg1;
    ssize_t            offset        = 0;
    ssize_t            status;
    
    status = recv(so, &buf, sizeof(buf), 0);
   // printf("cccccc");
    if (status == -1) {
      //  SC_log(LOG_NOTICE, "recv() failed: %s", strerror(errno));
        return FALSE;
    }
    
    cache_open();
    
    while (offset < status) {
        if ((offset + (ssize_t)ev_msg->total_size) > status) {
            //SC_log(LOG_NOTICE, "missed SYSPROTO_EVENT event, buffer not big enough");
            break;
        }
        switch (ev_msg->vendor_code) {
        case KEV_VENDOR_APPLE :
                switch (ev_msg->kev_class) {
                    case KEV_NETWORK_CLASS :
                        processEvent_Apple_Network(ev_msg);
                        break;
                        
                    default :
                        break;
                }
                break;
            default :
                break;
        }
        offset += ev_msg->total_size;
        ev_msg = (struct kern_event_msg *)(void *)&buf.bytes[offset];
    }
    return TRUE;
}


static Boolean initialize_store(void)
{
 SCDynamicStoreRef   store = SCDynamicStoreCreate(NULL,
                                 CFSTR("Kernel Event Monitor plug-in"),
                                 NULL,
                                 NULL);
    if (store == NULL) {
        NSLog(@"SCDynamicStoreCreate() failed: %s", SCErrorString(SCError()));
        return (FALSE);
    }
    return (TRUE);
}

void load_KernelEventMonitor()
{
    struct kev_request    kev_req;
    int            so;
    int            status;
    
    
    if (!initialize_store()) {
        NSLog(@"kernel event monitor disabled");
        return;
    }

    
    /* Open an event socket */
    so = socket(PF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT);
    if (so != -1) {
        /* establish filter to return events of interest */
        kev_req.vendor_code  = KEV_VENDOR_APPLE;
        kev_req.kev_class    = KEV_NETWORK_CLASS; // KEV_NETWORK_CLASS
        kev_req.kev_subclass = KEV_ANY_SUBCLASS;
        status = ioctl(so, SIOCSKEVFILT, &kev_req);
        if (status != 0) {
            // SC_log(LOG_ERR, "could not establish event filter, ioctl() failed: %s", strerror(errno));
            (void) close(so);
            so = -1;
        }
    } else {
        //SC_log(LOG_ERR, "could not open event socket, socket() failed: %s", strerror(errno));
    }
    
    if (so != -1) {
        int    yes = 1;
        
        status = ioctl(so, FIONBIO, &yes);
        if (status) {
            (void) close(so);
            so = -1;
        }
    }
    
    if (so == -1) {
        return;
    }
    
    S_kev_queue = dispatch_queue_create("com.apple.SystemConfiguration.KernelEventMonitor", NULL);
    S_kev_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, so, 0, S_kev_queue);
    dispatch_source_set_cancel_handler(S_kev_source, ^{
        close(so);
    });
    dispatch_source_set_event_handler(S_kev_source, ^{
        os_activity_t    activity;
        Boolean        ok;
        
        activity = os_activity_create("processing network kernel events",
                                      OS_ACTIVITY_CURRENT,
                                      OS_ACTIVITY_FLAG_DEFAULT);
        os_activity_scope(activity);
        
        ok = eventCallback(so);
        if (!ok) {
           NSLog(@ "kernel event monitor disabled");
            dispatch_source_cancel(S_kev_source);
        }
        
    });
    return;
}

static void prime(void)
{

    
    dispatch_resume(S_kev_source);
   // schedule_timer();
    
    return;
}

void prime_KernelEventMonitor()
{
    dispatch_async(S_kev_queue, ^{ prime(); });
    return;
}
#include<ifaddrs.h>


int main(int argc, const char * argv[]) {
    
    struct ifaddrs* if_addrs=NULL;
    struct ifaddrs*  if_addr=NULL;
    load_KernelEventMonitor();
    prime_KernelEventMonitor();
    dispatch_main();
    printf("Hello, xnu\n");
    
    return 0;
}


