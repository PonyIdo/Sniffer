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
  struct packets_node_t *next;
} packets_node;


typedef struct packets_lst_t {
  struct packets_node_t *first;
  struct packets_node_t *last;
} packets_lst;


packets_lst *lst; /* FIFO */

static struct packets_node_t* get_packet(void){
  // check if first exists
  if (!lst->first) return NULL;

  // store first value
  struct packets_node_t *packet = lst->first;

  return packet;
}

static struct packets_node_t* pop_packet(void){
  // check if first exists
  if (!lst->first) return NULL;

  // store first value
  struct packets_node_t *packet = lst->first;

  // remove first
  lst->first = lst->first->next;

  return packet;
}


static void add_packet(struct sk_buff *packet){
  // place the packet in a node
  struct packets_node_t *new_last = kmalloc(sizeof(struct packets_node_t), GFP_KERNEL | __GFP_ZERO);
  if (!new_last) return;

  new_last->packet = packet;
  new_last->next = NULL;

  // add the node to the back of the list
  if (lst->last) {
    lst->last->next = new_last;
  }
  else {
    lst->first = new_last;
  }

  lst->last = new_last;
}



//================== DEVICE FUNCTIONS ===========================t
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
static unsigned int current_read_mode = 0;
#define READ_MODE_LEN 0
#define READ_MODE_DATA 1
#define READ_MODE_NETWORK_OFFSET 2
#define READ_MODE_TRANSPORT_OFFSET 3

static ssize_t device_read( struct file* file,
                            char __user* buffer,
                            size_t       length,
                            loff_t*      offset )
{
  unsigned char *data;
  uint32_t len;
  uint16_t network_offset;
  uint16_t transport_offset;

  struct packets_node_t *node = get_packet();
  if (!node) return -EWOULDBLOCK;

  struct sk_buff *packet = node->packet;
  if (!packet) {
    pop_packet();
    kfree(node);
    return -EWOULDBLOCK;
  }

  printk( "Invocing device_read");
  if (!packet) return -EWOULDBLOCK;

  len = packet->len;

  switch (current_read_mode) {
    case READ_MODE_LEN:
      if (length < sizeof(len)) {
        free_packet(packet, node);
        return -ENOSPC;
      }

      if (copy_to_user(buffer, &len, sizeof(len))) {
        free_packet(packet, node);
        return -EFAULT;
      }

      return sizeof(len);


    case READ_MODE_DATA:
      data = packet->data;

      if (length < len) {
        free_packet(packet, node);
        return -ENOSPC;
      }

      if (copy_to_user(buffer, data, len)) {
        free_packet(packet, node);
        return -EFAULT;
      }

      return len;


    case READ_MODE_NETWORK_OFFSET:
      network_offset = (uint16_t)(packet->network_header);

      if (length < sizeof(network_offset)) {
        free_packet(packet, node);
        return -ENOSPC;
      }

      if (copy_to_user(buffer, &network_offset, sizeof(network_offset))) {
        free_packet(packet, node);
        return -EFAULT;
      }

      return sizeof(network_offset);


    case READ_MODE_TRANSPORT_OFFSET:
      transport_offset = (uint16_t)(packet->transport_header);

      if (length < sizeof(transport_offset)) {
        free_packet(packet, node);
        return -ENOSPC;
      }

      if (copy_to_user(buffer, &transport_offset, sizeof(transport_offset))) {
        free_packet(packet, node);
        return -EFAULT;
      }

      pop_packet();
      return sizeof(transport_offset);


    default:
      free_packet(packet, node);
      return -EINVAL;
  }
}

static void free_packet(struct sk_buff *packet, struct packets_node_t *node){
  pop_packet();
  kfree_skb(packet);
  kfree(node);
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
  switch (ioctl_command_id) {
    case SNIFFER_SET_MODE:
      unsigned int mode;

      if (copy_from_user(&mode, (unsigned int __user *)ioctl_param, sizeof(unsigned int))) {
        return -EFAULT;  // failed to copy from userspace
      }

      current_read_mode = mode;
      printk(KERN_DEBUG "Mode set to %u\n", current_read_mode);
      return 0;

    default:
      return -EINVAL; // unknown ioctl command
  }
}



// --------------------------------------------
// Hook function
static unsigned int handle_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *ip_header = ip_hdr(skb);
  if (ip_header)
    printk(KERN_DEBUG "[sniffer] caught src %pI4 dest %pI4!\n", &ip_header->saddr, &ip_header->daddr);

  printk(KERN_DEBUG "size: %u %u\noffsets: %u %u", skb->len, skb->truesize, skb->network_header, skb->transport_header);

  add_packet(skb);
  return NF_STOLEN;
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

    lst = kmalloc(sizeof(struct packets_lst_t), GFP_KERNEL | __GFP_ZERO);
    if (!lst) return -ENOMEM;

    netfilter_hook = kmalloc(sizeof(const struct nf_hook_ops), GFP_KERNEL | __GFP_ZERO);
    netfilter_hook->hook = handle_packet;
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

  packets_node *cur = lst->first;
  while (cur != NULL) {
    packets_node *next = cur->next;

    if (cur->packet)
      kfree_skb(cur->packet);

    kfree(cur);
    cur = next;
  }
  kfree(lst);

  printk( "removing is successful. ");

}

//---------------------------------------------------------------
module_init(simple_init);
module_exit(simple_cleanup);

//========================= END OF FILE =========================