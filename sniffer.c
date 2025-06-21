#undef __KERNEL__
#define __KERNEL__
#undef MODULE
#define MODULE

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


MODULE_LICENSE("Dual BSD/GPL");

//Our custom definitions of IOCTL operations
#include "sniffer.h"



typedef struct packets_node_t {
  struct sk_buff *packet;
  packets_node_t *next;
} packets_node;


typedef struct packets_lst_t {
  packets_node_t *first;
  packets_node_t *last;
} packets_lst;


packets_lst *lst; /* LIFO */


static packets_node* get_packet(){
  packets_node* curr;
  if (head == NULL){
    return NULL;
  }

  curr = head;
  head = next;
}



static void add_packet(){
  packets_node* curr;
  if (head == NULL){
    return NULL;
  }

  curr = head;
  head = next;
}



//================== DEVICE FUNCTIONS ===========================
static int device_open( struct inode* inode,
                        struct file*  file )
{
  printk("Invoking device_open(%p)\n", file);


  return SUCCESS;
}

//---------------------------------------------------------------
static int device_release( struct inode* inode,
                           struct file*  file)
{
  printk("Invoking device_release(%p,%p)\n", inode, file);

  return SUCCESS;
}

//---------------------------------------------------------------
// a process which has already opened
// the device file attempts to read from it
static ssize_t device_read( struct file* file,
                            char __user* buffer,
                            size_t       length,
                            loff_t*      offset )
{


  // read doesnt really do anything (for now)
  printk( "Invocing device_read");
  //invalid argument error

  curr_channel = get_channel(file_slot->slot_number, file_slot->channel_id);



  return -EINVAL;
}

//---------------------------------------------------------------
// a processs which has already opened
// the device file attempts to write to it
static ssize_t device_write( struct file*       file,
                             const char __user* buffer,
                             size_t             length,
                             loff_t*            offset)
{
  // return the number of input characters used
  return -1;
}

//----------------------------------------------------------------
static long device_ioctl( struct   file* file,
                          unsigned int   ioctl_command_id,
                          unsigned long  ioctl_param )
{
  return SUCCESS;
}



// --------------------------------------------
// Hook function
static unsigned int drop_google(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    //struct udphdr *udp_header;
    ip_header = ip_hdr(skb);

    /*ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;

    //if (ip_header->protocol == IPPROTO_UDP)*/
    printk(KERN_DEBUG "caught src %pI4 dest %pI4!\n", &ip_header->saddr, &ip_header->daddr);
    return NF_ACCEPT;
}





//==================== DEVICE SETUP =============================

// This structure will hold the functions to be called
// when a process does something to the device we created
struct file_operations Fops = {
  .owner	  = THIS_MODULE, 
  .read           = device_read,
  .write          = device_write,
  .open           = device_open,
  .unlocked_ioctl = device_ioctl,
  .release        = device_release,
};



struct nf_hook_ops *netfilter_hook;








//---------------------------------------------------------------
// Initialize the module - Register the character device
static int __init simple_init(void)
{
    int rc = -1;
    // init dev struct

    // Register driver capabilities. Obtain major num
    rc = register_chrdev( MAJOR_NUM, DEVICE_RANGE_NAME, &Fops );

    // Negative values signify an error
    if( rc < 0 ) {
        return rc;
    }

    netfilter_hook = kmalloc(sizeof(const struct nf_hook_ops), GFP_KERNEL | __GFP_ZERO);
    netfilter_hook->hook = drop_google;
    netfilter_hook->hooknum = NF_INET_PRE_ROUTING;
    netfilter_hook->pf = PF_INET;
    netfilter_hook->priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, netfilter_hook);
    
    
    printk( "Registeration is successful. ");


    return 0;
}

//---------------------------------------------------------------
static void __exit simple_cleanup(void)
{
    // Unregister the device
    // Should always succeed
    unregister_chrdev(MAJOR_NUM, DEVICE_RANGE_NAME);
    nf_unregister_net_hook(&init_net, netfilter_hook);
    kfree(netfilter_hook);

    printk( "removing is successful. ");

}

//---------------------------------------------------------------
module_init(simple_init);
module_exit(simple_cleanup);

//========================= END OF FILE =========================
