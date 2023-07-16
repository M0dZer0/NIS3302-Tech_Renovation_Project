#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

unsigned int controlled_protocol = 0;	// 要控制报文的协议类型	1:ICMP 6:TCP 17:UDP
unsigned short controlled_srcport = 0;	// 要控制报文的源端口，0表示控制所有源端口的报文，只对TCP和UDP协议有效
unsigned short controlled_dstport = 0;	// 要控制报文的目的端口，只对TCP和UDP协议有效
unsigned int controlled_saddr = 0;	// 要控制报文的源IP地址
unsigned int controlled_daddr = 0;	// 要控制报文的目的IP地址 

void display_usage(char *commandname)
{
	printf("Usage 1: %s \n", commandname);	// 不跟任何参数，即关闭防火墙功能
	printf("Usage 2: %s -x saddr -y daddr -m srcport -n dstport \n", commandname);
}

int getpara(int argc, char *argv[]){
	int optret;	// 用于保存getopt()的返回值
	unsigned short tmpport;	// 用于保存端口号的临时变量
	optret = getopt(argc,argv,"pxymnh");	// 读取命令行参数
	while( optret != -1 ) {
//			printf(" first in getpara: %s\n",argv[optind]);
        	switch( optret ) {
        	case 'p':
        		if (strncmp(argv[optind], "ping",4) == 0 )
					controlled_protocol = 1;
				else if ( strncmp(argv[optind], "tcp",3) == 0  )
					controlled_protocol = 6;
				else if ( strncmp(argv[optind], "udp",3) == 0 )
					controlled_protocol = 17;
				else {
					printf("Unkonwn protocol! please check and try again! \n");
					exit(1);
				}
        		break;
         case 'x':   // get source ipaddr
				if ( inet_aton(argv[optind], (struct in_addr* )&controlled_saddr) == 0){
					printf("Invalid source ip address! please check and try again! \n ");
					exit(1);
				}
         	break;
         case 'y':   //get destination ipaddr
				if ( inet_aton(argv[optind], (struct in_addr* )&controlled_daddr) == 0){
					printf("Invalid destination ip address! please check and try again! \n ");
					exit(1);
				}
         	break;
         case 'm':   // get source port
				tmpport = atoi(argv[optind]);
				if (tmpport == 0){
					printf("Invalid source port! please check and try again! \n ");
					exit(1);
				}
				controlled_srcport = htons(tmpport);
         	break;
        case 'n':   // get destination port
				tmpport = atoi(argv[optind]);
				if (tmpport == 0){
					printf("Invalid source port! please check and try again! \n ");
					exit(1);
				}
				controlled_dstport = htons(tmpport);
         	break;
         case 'h':   /* fall-through is intentional */
         case '?':
         	display_usage(argv[0]);
         	exit(1);;
                
         default:
				printf("Invalid parameters! \n ");
         	display_usage(argv[0]);
         	exit(1);;
        	}
		optret = getopt(argc,argv,"pxymnh");	// get next parameter
	}
}

int main(int argc, char *argv[]){
	char controlinfo[32];	// 规则信息的缓冲区
	int controlinfo_len = 0;	// 规则信息的长度
	int fd;	// 用于保存设备文件打开后的文件描述符
	struct stat buf;	// 用于获取设备文件是否存在的临时缓冲区
	
	if (argc == 1)	// no parameter, cancel the filter
		controlinfo_len = 0; //cancel the filter
	else if (argc > 1){
		getpara(argc, argv);	
		/*将规则信息按：要控制报文的协议类型，要控制报文的源IP地址，要控制报文的目的IP地址，要控制报文的源端口，要控制报文的目的端口
		的顺序，每个字段占4个字节来组织controlinfo缓冲区，缓冲区中的内容经过写设备传向内核模块时，内核模块按上述格式解析规则信息*/
		*(int *)controlinfo = controlled_protocol;
		*(int *)(controlinfo + 4) = controlled_saddr;
		*(int *)(controlinfo + 8) = controlled_daddr;
		*(int *)(controlinfo + 12) = controlled_srcport;
		*(int *)(controlinfo + 16) = controlled_dstport;
		controlinfo_len = 20;
		/*在这段代码中，*(int *) 是一种类型转换操作。它将一个指针 controlinfo 强制转换为一个 int 类型的指针，
		然后通过解引用操作符 * 将其指向的内存视为一个 int 类型的变量。这段代码的目的是将一些控制信息存储到 controlinfo 数组中。
		通过将指针转换为 int 类型的指针，代码可以将 controlled_protocol、controlled_saddr、controlled_daddr、
		controlled_srcport 和 controlled_dstport 这些变量的值分别存储到 controlinfo 数组的不同位置。
		例如，*(int *)controlinfo = controlled_protocol; 将 controlled_protocol 的值存储到 controlinfo 数组的开始位置，
		相当于 controlinfo[0] = controlled_protocol;。请注意，这段代码假设 controlinfo 数组的大小至少为 32 字节，
		并且变量的大小与 int 类型相同（通常是 4 字节），以确保正确存储和访问这些变量的值。*/
	}
	
//	printf("input info: p = %d, x = %d y = %d m = %d n = %d \n", controlled_protocol,controlled_saddr,controlled_daddr,controlled_srcport,controlled_dstport);

	if (stat("/dev/controlinfo",&buf) != 0){
		if (system("mknod /dev/controlinfo c 124 0") == -1){
			printf("Cann't create the devive file ! \n");
			printf("Please check and try again! \n");
			exit(1);
		}
	}
	fd =open("/dev/controlinfo",O_RDWR,S_IRUSR|S_IWUSR);
	if (fd > 0)
	{
		write(fd,controlinfo,controlinfo_len);
	}
	else {
		perror("can't open /dev/controlinfo \n");
	 	exit(1);
	}
	close(fd);
}
