#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <net/sock.h>
#include <net/netlink.h>

#include <linux/types.h>
#include <linux/stat.h>
#include <linux/netlink.h>

#define NETLINK_TEST     30
#define MSG_LEN            125
#define USER_PORT        100

//#define TASK_COMM_LEN 16
//#define Netlink_TEST 29
#define AUDITPATH "/home/zc-zhai/Documents/SafeGuard"
//#define MAX_LENGTH 256
#define LOGIN_MESSAGE "Identity Certification Passed!"
#define LOGOUT_MESSAGE "Service Exit!                 "

void ** sys_call_table;
asmlinkage long(* orig_open)(const char * pathname, int flags, mode_t mode);
asmlinkage long(* orig_unlink)(const char *pathname);
asmlinkage long(* orig_mkdir)(const char *pathname, mode_t mode);
asmlinkage long(* orig_rmdir)(const char *pathname);
asmlinkage long(* orig_chmod)(const char *pathname, mode_t mode);
asmlinkage long(* orig_rename)(const char *oldpath, const char *newpath);
asmlinkage long(* orig_chdir)(const char *path);
//static u32 pid = 0;
//static struct sock *nl_sk = NULL;
unsigned int clear_and_return_cr0(void);
//void *get_sys_call_table(void);
//void *get_system_call(void);
//void netlink_init(void);
//void nl_data_ready (struct sock * sk, int len);
static void __exit audit_exit(void);
//void netlink_release(void);
struct sock *nlsk = NULL;
extern struct net init_net;
int send_usrmsg(char *pbuf, uint16_t len);
static void netlink_rcv_msg(struct sk_buff *skb);
int test_netlink_init(void);
void test_netlink_exit(void);
asmlinkage long hacked_open(const char * pathname, int flags, mode_t mode);
asmlinkage long hacked_unlink(const char *pathname);
asmlinkage long hacked_mkdir(const char *pathname, mode_t mode);
asmlinkage long hacked_rmdir(const char *pathname);
asmlinkage long hacked_chmod(const char *pathname, mode_t mode);
asmlinkage long hacked_rename(const char *oldpath, const char *newpath);
asmlinkage long hacked_chdir(const char *path);
unsigned long **get_sys_call_table(void);

int state = 0;
char pid[5];

MODULE_LICENSE("GPL");
/*
struct idt_descriptor{
    unsigned short off_low;
    unsigned short sel;
    unsigned char none,flags;
    unsigned short off_high;
};
*/
static int __init audit_init(void){

     
    unsigned int orig_cr0 = clear_and_return_cr0();// 清除控制寄存器CR0的写保护检査控制位, 并保存 CR0 寄存器的原始值
    printk("+ LOADING MODULE\n");
    printk("+ GARNER AND CLEAR CR0\n");
    sys_call_table = (void **)get_sys_call_table(); //获取系统调用人口地址表的首地址
    printk("+ SYS_CALL_TABLE FOUND AT %lx\n",(unsigned long)sys_call_table); //输出系统调用人口地址表的首地址
    
    orig_open = sys_call_table[__NR_open]; /*保存open系统调用的原始处理函数人口地址,
                                            NR_open为 open的系统调用号,该号对应 open 系统调用处理函数
                                            在系统调用人口地址表的位置*/
    orig_unlink = sys_call_table[__NR_unlink];
    orig_mkdir = sys_call_table[__NR_mkdir];
    orig_rmdir = sys_call_table[__NR_rmdir];
    orig_chmod = sys_call_table[__NR_chmod];
    orig_rename = sys_call_table[__NR_rename];
    orig_chdir = sys_call_table[__NR_chdir];
    printk("+ GARNER ORIGINAL SYS_CALL\n");
    sys_call_table[__NR_open] = hacked_open; //重载open 系统调用的处理函数人口地址
    sys_call_table[__NR_unlink] = hacked_unlink;
    sys_call_table[__NR_mkdir] = hacked_mkdir;
    sys_call_table[__NR_rmdir] = hacked_rmdir;
    sys_call_table[__NR_chmod] = hacked_chmod;
    sys_call_table[__NR_rename] = hacked_rename;
    sys_call_table[__NR_chdir] = hacked_chdir;
    printk("+ HACKING SYS_CALL\n");
    asm volatile ("movl %%eax, %%cr0"::"a"(orig_cr0)); //恢复控制寄存器CR0的值,即恢复其写保护检查控制位
    printk("+ RECOVER CR0\n");
    test_netlink_init();//进行Netlink相关的初始化
    list_del_init(&__this_module.list);
    kobject_del(&THIS_MODULE->mkobj.kobj);

    return 0;
}

unsigned long **get_sys_call_table(void)
{
    unsigned long ptr;
    unsigned long *p;

    for (ptr = (unsigned long) sys_close; ptr < (unsigned long) &loops_per_jiffy; ptr += sizeof(void *))
    {
             
        p = (unsigned long *) ptr;

        if (p[__NR_close] == (unsigned long) sys_close)
        {
            return (unsigned long **) p;
        }
    }
    
    return NULL;
}
/*
void *get_system_call(void) {       //该函数用于获得系统调用处理西数的入口地址,即Linux 系统中0x80号中断的处理函数地址
    
    unsigned char idtr[6];
    unsigned long base;
    //存储中断向量表的首地址
    struct idt_descriptor desc;
    asm ("sidt %0" : " = m" (idtr)); //取出中断向量寄存器的内容
    printk("&idtr[2] = %lx\n", &idtr[2]);
    base= *((unsigned long *)&idtr[2]); //获得中断向量表的首地址
    printk("base = %lx\n",base);
    memcpy(&desc,(void *)(base+(0x80*8)),sizeof(desc));//获得实现系统调用的中断(对应的中断号为0x80)信息,
                                                        //由于每个中断的信息结构占8字节,所以该中断的信息在中断向量表中的偏移地址为(Ox80+8)
    printk("desc = %lx\n",desc);
    return((void *)((desc.off_high << 16) + desc.off_low)); //将高地址的 16左移
}

void *get_sys_call_table(void) {
    
    void * system_call = get_system_call(); //获得系统调用处理函数(0x80号中断)的地址
    printk("system_call = %lx\n", system_call);
    unsigned char * p;  //临时性指针变量
    unsigned long sct;  //缓存系统调用人口地址表的首地址指针
    int count = 0;

    p = (unsigned char * ) system_call;   //下面的循环在系统调用处理函数的代码段中搜索call指令的位置,call指令的指令码为"Oxff1485" 
    printk("p = %lx\n", p);
    while(!((*p == 0xff) && (*(p+1) == 0x14)&&(*(p+2) == 0x85))){
        p++;
        if (count ++> 500) { //搜索范围超出了系统调用处理函数的代码段长度,终止搜索
            count = -1; //设置不成功标志
            break;
        }
    }
    if(count != -1){    //判别是搜索成功终止,还是搜索范围超出终止
        p += 3; //跳过指令码,获取第一个操作数,该操作数即为系统调用人口地址表的首地址
        sct = *((unsigned long *)p);
    }
    else
        sct = 0;    //没有成功获得系统调用入口地址表的首地址
    printk("sct = %lx\n", sct);
    return((void *)sct); //返回系统调用人口地址表的首地址
}
*/
unsigned int clear_and_return_cr0(void){ //清除控制寄存器CR0中的写保护检查控制位
    unsigned int cr0 = 0;
    unsigned int ret;   //保存CR0寄存器的原始值

    //asm volatile ("movl % %eax, % % cr0"::"a"(orig_cr0));
    asm volatile ("movl %%cr0, %%eax":"=a"(cr0)); //将CR0寄存器的原始值读到变量cr0中
    ret = cr0;  //将CR0 寄存器的原始值保存至 ret中
    cr0 &= 0xfffeffff;    //修改CR0的值,将其第16位(即写保护检查控制位)置0

    asm volatile ("movl %%eax, %%cr0"::"a"(cr0)); /* 将清除写保护检查控制位后的值回写至CR0寄存器*/

    return ret; //将 CR0 寄存器的原始值返回, 以便于将来恢复 CR0 寄存器的值
}
/*
void netlink_init(void){ //创建一个Netlink类型的SOCKET接口,要基于该接口与应用程序进行通信
    nl_sk = netlink_kernel_create(Netlink_TEST, 0, nl_data_ready, THIS_MODULE);

    if(!nl_sk){ //创建失败,进行相关的资源释放
        printk(KERN_ERR"net_link:Cannot create netIink socket.\n"); 
        if(nl_sk != NULL)
            sock_release(nl_sk->sk_socket);
    }
    else    //创建成功,输出提示信息
        printk("net_link: create socket ok.\n");
}

void nl_data_ready (struct sock * sk, int len){     //在基于 Netlink 的 SOCKET接口有数据到达时,Linux内核自动会调用该函数
    struct sk_buff * skb; //消息报文缓冲区指针
    struct nlmsghdr * nlh; //Netlink消息头指针
    skb = skb_dequeue(&(sk->sk_receive_queue));     //调用 skb_dequeue,从该套接字对应的消息到达链(sk->sk_receive_queue)上,取出一个到达的消息

    if(skb->len >= NLMSG_SPACE(0)){ //NLMSG_SPACE(0)表示最短内容的消息长度,即纯消息头的长度,到达消息若小于该长度是无效消息
        nlh = (struct nlmsghdr *)skb->data; //取出到达消息的内容,即Netlink消息头
        pid = nlh->nlmsg_pid; //获取发送该消息进程的标识符
        printk("net_link:   pid is %d, \n",pid);
        kfree_skb(skb); //释放处理过的消息
    }
    
    return;
}*/

static void __exit audit_exit(void){
    unsigned int orig_cr0 = clear_and_return_cr0();  //清除CR0寄存器写保护检查控制位
    sys_call_table[__NR_open] = orig_open;   //恢复原始open系统调用处理函数
    asm volatile("movl %%eax, %%cr0" : : "a"(orig_cr0));    //恢复控制寄存器CR0的值，即恢复其写保护检查控制位
    test_netlink_exit();
    printk("+ UNLOADING MODULE\n");
}
/*
void netlink_release(void){
    if(nl_sk != NULL)
        sock_release(nl_sk -> sk_socket);   //释放Netlink资源
}*/

int send_usrmsg(char *pbuf, uint16_t len)
{
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;

    int ret;

    /* 创建sk_buff 空间 */
    nl_skb = nlmsg_new(len, GFP_ATOMIC);
    if(!nl_skb)
    {
        printk("- NETLINK ALLOC FAILED\n");
        return -1;
    }

    /* 设置netlink消息头部 */
    nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_TEST, len, 0);
    if(nlh == NULL)
    {
        printk("- NLMSG_PUT FAILED\n");
        nlmsg_free(nl_skb);
        return -1;
    }

    /* 拷贝数据发送 */
    memcpy(nlmsg_data(nlh), pbuf, len);
    ret = netlink_unicast(nlsk, nl_skb, USER_PORT, MSG_DONTWAIT);

    return ret;
}

static void netlink_rcv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    char *umsg = NULL;
    char *kmsg = "HELLO USER!";
    char *lmsg = "GOODBYE USER!";
    char *mmsg = "PID RECEIVED!";

    if(skb->len >= nlmsg_total_size(0))
    {
        nlh = nlmsg_hdr(skb);
        umsg = NLMSG_DATA(nlh);
        if(strcmp(umsg,LOGIN_MESSAGE)==0)
        {
            printk("+ KERNEL RECV FROM USER: %s\n", umsg);
            state = 1;
            printk("+ STATUS: VALID USER %x\n", state);
            send_usrmsg(kmsg, strlen(kmsg));
        }
        
	    else if(strcmp(umsg,LOGOUT_MESSAGE)==0)
        {
            printk("+ KERNEL RECV FROM USER: %s\n", umsg);
            state = 0;
            printk("+ STATUS: SERVICE STOPPED %x\n", state);
            send_usrmsg(lmsg, strlen(lmsg));
        }
	    else
	    {
	        strncpy(pid,umsg,5);
	        pid[4] = '\0';
            printk("+ KERNEL RECV FROM USER: %s\n", pid);
	        printk("+ VALID PID: %s\n", pid);
	        send_usrmsg(mmsg, strlen(mmsg));
	    }
    }
}

struct netlink_kernel_cfg cfg = { 
        .input  = netlink_rcv_msg, /* set recv callback */
};  

int test_netlink_init(void)
{
    /* create netlink socket */
    nlsk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if(nlsk == NULL)
    {   
        printk("- NETLINK_KERNEL_CREATE ERROR\n");
        return -1; 
    }   
    printk("+ NETLINK_KERNEL READY\n");
    printk("+ STATUS: READY FOR CERTIFICATION %x\n", state);
    
    return 0;
}

void test_netlink_exit(void)
{
    if (nlsk){
        netlink_kernel_release(nlsk); /* release ..*/
        nlsk = NULL;
    }   
    printk("+ NETLINK_KERNEL EXIT\n");
}

asmlinkage long hacked_open(const char * pathname, int flags, mode_t mode){ 
    long ret;
    char c_pid[5];
    int tmp_int, count = 4;
    int tmp_curr_pid = current->pid;	

    while(count > 0){
    	tmp_int = tmp_curr_pid % 10;
	    c_pid[count-1] = tmp_int + '0';
	    tmp_curr_pid /= 10;
	    count--;
    }
    c_pid[4] = '\0';

    if(pathname == NULL){
        return -1;
    }
    
    if ((state == 1 && strncmp(pid,c_pid,4)==0) || (strncmp(pathname,AUDITPATH,33)!=0)){
        if (strstr(pathname,"SafeGuard")!=NULL){printk("OPEN FILE: %s\n",pathname);}
        ret = orig_open(pathname, flags, mode);
        return ret;
    }
    else{
	    printk("CURRENT PID: %s\n",c_pid);
	    printk("VALID PID:   %s\n",pid);
        printk("- OPEN FAILED : PERMISSION DENIED\n");
        return -1;
    }
}

asmlinkage long hacked_unlink(const char *pathname){
    long ret;
    char c_pid[5];
    int tmp_int, count = 4;
    int tmp_curr_pid = current->pid;	

    while(count > 0){
    	tmp_int = tmp_curr_pid % 10;
	    c_pid[count-1] = tmp_int + '0';
	    tmp_curr_pid /= 10;
	    count--;
    }
    c_pid[4] = '\0';

    if(pathname == NULL){
        return -1;
    }
    
    if ((state == 1 && strncmp(pid,c_pid,4)==0) || (strncmp(pathname,AUDITPATH,33)!=0)){
        if (strstr(pathname,"SafeGuard")!=NULL){printk("DELETE FILE: %s\n",pathname);}
	//printk("11111111111111111111\n");
        ret = orig_unlink(pathname);
        return ret;
    }
    else{
	    printk("CURRENT PID: %s\n",c_pid);
	    printk("VALID PID:   %s\n",pid);
        printk("- DELETE FAILED : PERMISSION DENIED\n");
        return -1;
    }
}

asmlinkage long hacked_mkdir(const char *pathname, mode_t mode){
    long ret;
    char c_pid[5];
    int tmp_int, count = 4;
    int tmp_curr_pid = current->pid;	

    while(count > 0){
    	tmp_int = tmp_curr_pid % 10;
	    c_pid[count-1] = tmp_int + '0';
	    tmp_curr_pid /= 10;
	    count--;
    }
    c_pid[4] = '\0';

    if(pathname == NULL){
        return -1;
    }
    
    if ((state == 1 && strncmp(pid,c_pid,4)==0) || (strncmp(pathname,AUDITPATH,33)!=0)){
        if (strstr(pathname,"SafeGuard")!=NULL){printk("CREATE PATH: %s\n",pathname);}
        ret = orig_mkdir(pathname,mode);
        return ret;
    }
    else{
	    printk("CURRENT PID: %s\n",c_pid);
	    printk("VALID PID:   %s\n",pid);
        printk("- MKDIR FAILED : PERMISSION DENIED\n");
        return -1;
    }
}

asmlinkage long hacked_rmdir(const char *pathname){
    long ret;
    char c_pid[5];
    int tmp_int, count = 4;
    int tmp_curr_pid = current->pid;	

    while(count > 0){
    	tmp_int = tmp_curr_pid % 10;
	    c_pid[count-1] = tmp_int + '0';
	    tmp_curr_pid /= 10;
	    count--;
    }
    c_pid[4] = '\0';

    if(pathname == NULL){
        return -1;
    }
    
    if ((state == 1 && strncmp(pid,c_pid,4)==0) || (strncmp(pathname,AUDITPATH,33)!=0)){
        if (strstr(pathname,"SafeGuard")!=NULL){printk("DELETE PATH: %s\n",pathname);}
        ret = orig_rmdir(pathname);
        return ret;
    }
    else{
	    printk("CURRENT PID: %s\n",c_pid);
	    printk("VALID PID:   %s\n",pid);
        printk("- RMDIR FAILED : PERMISSION DENIED\n");
        return -1;
    }
}

asmlinkage long hacked_chmod(const char *pathname, mode_t mode){
    long ret;
    char c_pid[5];
    int tmp_int, count = 4;
    int tmp_curr_pid = current->pid;	

    while(count > 0){
    	tmp_int = tmp_curr_pid % 10;
	    c_pid[count-1] = tmp_int + '0';
	    tmp_curr_pid /= 10;
	    count--;
    }
    c_pid[4] = '\0';

    if(pathname == NULL){
        return -1;
    }
    
    if ((state == 1 && strncmp(pid,c_pid,4)==0) || (strncmp(pathname,AUDITPATH,33)!=0)){
        if (strstr(pathname,"SafeGuard")!=NULL){printk("CHMOD FILE: %s\n",pathname);}
	//printk("11111111111111111111\n");
        ret = orig_chmod(pathname,mode);
        return ret;
    }
    else{
	    printk("CURRENT PID: %s\n",c_pid);
	    printk("VALID PID:   %s\n",pid);
        printk("- CHMOD FAILED : PERMISSION DENIED\n");
        return -1;
    }
}

asmlinkage long hacked_rename(const char *oldpath, const char *newpath){
    long ret;
    char c_pid[5];
    int tmp_int, count = 4;
    int tmp_curr_pid = current->pid;	

    while(count > 0){
    	tmp_int = tmp_curr_pid % 10;
	    c_pid[count-1] = tmp_int + '0';
	    tmp_curr_pid /= 10;
	    count--;
    }
    c_pid[4] = '\0';

    if(oldpath == NULL || newpath == NULL){
        return -1;
    }
    
    if ((state == 1 && strncmp(pid,c_pid,4)==0) || (strncmp(oldpath,AUDITPATH,33)!=0 && strncmp(newpath,AUDITPATH,33)!=0)){
        if (strstr(oldpath,"SafeGuard")!=NULL && strstr(newpath,"SafeGuard")!=NULL){printk("RENAME/REMOVE FILE: FROM %s TO %s\n",oldpath,newpath);}
        ret = orig_rename(oldpath,newpath);
        return ret;
    }
    else{
	    printk("CURRENT PID: %s\n",c_pid);
	    printk("VALID PID:   %s\n",pid);
        printk("- RENAME/REMOVE FAILED : PERMISSION DENIED\n");
        return -1;
    }
}

asmlinkage long hacked_chdir(const char *path){
    long ret;
    char c_pid[5];
    int tmp_int, count = 4;
    int tmp_curr_pid = current->pid;	

    while(count > 0){
    	tmp_int = tmp_curr_pid % 10;
	    c_pid[count-1] = tmp_int + '0';
	    tmp_curr_pid /= 10;
	    count--;
    }
    c_pid[4] = '\0';

    if(path == NULL){
        return -1;
    }
    
    if ((state == 1 && strncmp(pid,c_pid,4)==0) || strstr(path,"SafeGuard")==NULL){
        if (strstr(path,"SafeGuard")!=NULL){printk("CHDIR TO:%s\n",path);}
        ret = orig_chdir(path);
        return ret;
    }
    else{
	    printk("CURRENT PID: %s\n",c_pid);
	    printk("VALID PID:   %s\n",pid);
        printk("- CHDIR FAILED : PERMISSION DENIED\n");
        return -1;
    }
}

module_init(audit_init);
module_exit(audit_exit);


